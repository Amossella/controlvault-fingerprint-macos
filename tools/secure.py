"""Sessione cifrata ControlVault: handshake + comandi sicuri (cifra/decifra).
Basato su cvcrypto.py (crittografia verificata) e sulla sequenza enroll estratta dal log Frida.
"""
import os, struct, time, sys
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.expanduser("~/usbcfg/controlvault"))
import controlvault as C
import cvcrypto
from Crypto.Cipher import AES


class SecureSession:
    def __init__(self, dev):
        self.d = dev
        self.ak = self.hk = None
        self.handle = 0          # device handle (envelope)
        self.ihandle = 0         # CV internal handle (dalla open)
        self.seq = 0             # contatore di sequenza HMAC (open=0, ++ per operazione)

    def _raw(self, pkt, to=4000):
        self.d.dev.write(C.EP_OUT, pkt, timeout=to)
        try:
            notif = bytes(self.d.dev.read(C.EP_INT, 16, timeout=to))
        except Exception:
            notif = b""
        rlen = struct.unpack_from("<I", notif, 4)[0] if len(notif) >= 8 else 512
        return bytes(self.d.dev.read(C.EP_IN, max(rlen, 64), timeout=to)), notif

    def handshake(self, reinit=True):
        if reinit:
            self.d.init()
        hn = os.urandom(20)
        r = self.d.transact(C.build_envelope(0x00410023, hn + b"\x00" * 4, counter=2))
        n = cvcrypto.device_pubkey_from_0x23(r["data"])
        dn = cvcrypto.device_nonce_from_0x23(r["data"])
        self.handle = r["handle"]
        self.d.transact(C.build_envelope(0x00410024, cvcrypto.rsa_pkcs1v15_encrypt_le(hn, n),
                                         counter=2, handle=self.handle))
        self.ak, self.hk = cvcrypto.session_keys(hn, dn)
        return True

    def secure_cmd(self, cmd_word, data, to=6000, hmac_seq=None):
        """Invia un comando sicuro, ritorna (status, plaintext_data).
        hmac_seq: contatore di sequenza; se None, auto-incrementa (open deve passare 0)."""
        if hmac_seq is None:
            self.seq += 1
            hmac_seq = self.seq
        env = cvcrypto.build_secure_envelope(cmd_word, data, self.ak, self.hk,
                                             counter=2, handle=self.handle, hmac_seq=hmac_seq)
        resp, notif = self._raw(env, to=to)
        # Lo STATUS e' nell'envelope in chiaro (offset 20); il data_len a offset 40.
        status = struct.unpack_from("<I", resp, 20)[0]
        dlen_hdr = struct.unpack_from("<I", resp, 40)[0]
        iv = resp[24:40]
        ct = resp[44:]
        if len(ct) == 0 or len(ct) % 16 != 0:
            return status, b"", notif
        pt = AES.new(self.ak, AES.MODE_CBC, iv).decrypt(ct)
        # plaintext = data(dlen_hdr) || HMAC-SHA1(20) || PKCS7
        payload = pt[:dlen_hdr]
        return status, payload, notif

    # appID + userID del credential Windows Hello (il chip li usa come etichetta dell'oggetto).
    APPID = bytes.fromhex("ba978e77aab6ce4b8be58bda182d3ecf")           # GUID (16B)
    USERID = bytes.fromhex("c9ec6b4538d095771e8321cf091008da952965ac")   # 20B

    # --- verbi (dai template del log) ---
    def open(self):
        data = bytes.fromhex("00000000""04000000""4d000000""01000000""00000000""01000000""00000000""01000000""00000000")
        self.seq = 0
        st, pl, _ = self.secure_cmd(0x02410002, data, hmac_seq=0)
        # payload = inner_status(4) || inner_len(4) || handle(4)
        if st == 0 and len(pl) >= 12:
            self.ihandle = struct.unpack_from("<I", pl, 8)[0]
        return st, self.ihandle

    def open72(self, appid=None, userid=None):
        """Open con appID+userID (72B) — necessaria per REGISTRARE il template e ottenere l'handle."""
        appid = self.APPID if appid is None else appid
        userid = self.USERID if userid is None else userid
        data = (bytes.fromhex("00000000""04000000""4d000000""01000000") +
                struct.pack("<I", len(appid)) + appid +
                bytes.fromhex("01000000") +
                struct.pack("<I", len(userid)) + userid +
                bytes.fromhex("01000000""00000000"))
        # prima operazione di una sessione nuova (dopo handshake) -> seq=0
        self.seq = 0
        st, pl, _ = self.secure_cmd(0x02410002, data, hmac_seq=0)
        if st == 0 and len(pl) >= 12:
            self.ihandle = struct.unpack_from("<I", pl, 8)[0]
        return st, self.ihandle

    def capture(self, to=6000):
        # 0x66 (36B): status0|len4|ihandle | 0|len4|0x01 | 0|len4|0x23  (Windows usa 0x01, non 0x02)
        # risposta st=0 dlen=28: status0|len4(0x14)|R(20B)  -> R = capture result
        ih = struct.pack("<I", self.ihandle)
        data = (bytes.fromhex("0000000004000000") + ih +
                bytes.fromhex("000000000400000001000000") +
                bytes.fromhex("000000000400000023000000"))
        st, pl, notif = self.secure_cmd(0x02430066, data, to=to)
        R = pl[8:8 + 20] if len(pl) >= 28 else b""   # salta status/len interni
        return st, R, pl, notif

    def enroll_start(self, to=6000):
        # 0x8a (12B): status0|len4|0
        data = bytes.fromhex("000000000400000000000000")
        return self.secure_cmd(0x0241008a, data, to=to)

    def update_enroll(self, capture_result, to=6000):
        # 0x6c (48B): status0|len4|ihandle | 0|len4(0x14)|R(20B) | 02000000|00000000
        ih = struct.pack("<I", self.ihandle)
        data = (bytes.fromhex("0000000004000000") + ih +
                bytes.fromhex("0000000014000000") + capture_result +
                bytes.fromhex("0200000000000000"))
        return self.secure_cmd(0x0241006c, data, to=to)

    def reset(self):
        """Sblocca stato pendente (discard enroll + capture-wait) in chiaro."""
        self.d.init()
        for cw in (0x0440006d, 0x04400068):   # discard, capture-wait
            try:
                self.d.transact(C.build_envelope(cw, bytes.fromhex("000000000400000000000000"), counter=2))
            except Exception:
                pass

    def enroll(self, target_stages=4, max_stages=12, on_event=None):
        """Enroll completo nella sessione cifrata + commit. target_stages = tocchi richiesti
        (Windows=4). Ritorna (ok, last_status, stages, commit_status)."""
        def ev(m):
            if on_event: on_event(m)
            else: print(m, flush=True)
        self.reset()
        st, ih = self.open()
        ev("open status=0x%x ihandle=0x%x" % (st, ih))
        if st != 0:
            return False, st, 0, None, 0, b""
        # Loop: capture(arma, R) -> dito -> update(R). Ogni update ritorna un template-ref (feat[20:40]).
        stages = 0
        last_ref = None
        last = 0
        for i in range(max_stages):
            st, R, pl, notif = self.capture()
            ev("[tocco %d] capture st=0x%x R=%dB" % (i + 1, st, len(R)))
            if st != 0 or len(R) < 20:
                ev("   capture non pronta st=0x%x -> stop" % st); break
            ev("   >> APPOGGIA E SOLLEVA IL DITO")
            if not self.wait_finger():
                ev("   timeout dito"); break
            st, feat, notif = self.update_enroll(R)
            last = st
            if st == 0:
                stages += 1
                if len(feat) >= 40:
                    last_ref = feat[20:40]
                ev("   STAGE OK #%d feat=%dB ref=%s" % (stages, len(feat), (last_ref or b'').hex()))
                if stages >= target_stages:
                    ev("   >>> %d stadi completati -> COMMIT" % stages)
                    break
            elif st in (0x59, 0x8c):
                ev("   >>> enrollment ready (st=0x%x) dopo %d stage -> COMMIT" % (st, stages))
                break
            else:
                ev("   update st=0x%x -> stop" % st)
                return False, st, stages, None, 0, b""
        if last_ref is None:
            return False, last, stages, None, 0, b""
        ev("COMMIT/REGISTER (sessione-72 appID+userID)...")
        handle, tid, cst = self.register_template(last_ref, on_event=ev)
        ev("  -> handle template = 0x%x  id=%s" % (handle, tid.hex()))
        return (handle != 0), last, stages, cst, handle, tid

    # TAIL metadati reali del commit Windows (contiene "BroadcomWBF").
    # Ultimo u32 = dimensione buffer output: 0x0800 -> restituisce il BLOB (commit#1),
    # 0 -> REGISTRA e restituisce l'HANDLE (commit#2). ERA QUESTO il bug (usavo sempre 0x0800).
    _TAIL_HEAD = bytes.fromhex(
        "0200000008000000000004000400000002000000150000000101ff0000000d00"
        "0c42726f6164636f6d5742460000000003000000")
    COMMIT_TAIL_BLOB = _TAIL_HEAD + bytes.fromhex("00080000")   # commit#1 -> blob
    COMMIT_TAIL_REG = _TAIL_HEAD + bytes.fromhex("00000000")    # commit#2 -> handle

    def commit(self, template20, register=False):
        # 0x6e (96B): status0|len4|ihandle | 0|len4(0x14)|ref(20B) | TAIL(56B)
        ih = struct.pack("<I", self.ihandle)
        tail = self.COMMIT_TAIL_REG if register else self.COMMIT_TAIL_BLOB
        data = (bytes.fromhex("0000000004000000") + ih +
                bytes.fromhex("0000000014000000") + template20 + tail)
        return self.secure_cmd(0x0241006e, data)

    @staticmethod
    def parse_commit(pl):
        """Risposta commit 0x6e REGISTRATA: 03000000 00000000 00000000 04000000 handle(4) [id20].
        Ritorna (handle, id20). Se la risposta e' il BLOB del template (non la registrazione),
        ritorna (0, b'')."""
        if len(pl) >= 20 and pl[4:12] == b"\x00" * 8 and pl[12:16] == b"\x04\x00\x00\x00":
            handle = struct.unpack_from("<I", pl, 16)[0]
            tid = pl[20:40] if len(pl) >= 40 else b""
            return handle, tid
        return 0, b""

    def register_template(self, ref20, on_event=None):
        """Flusso Windows: commit#1 (tail-blob, costruisce) in sessione-72, poi NUOVO handshake
        + open72 + commit#2 (tail-registrazione) -> handle. Ritorna (handle, id20, last_status)."""
        def ev(m):
            if on_event: on_event(m)
        last = None
        # commit#1: costruisce l'oggetto, restituisce il blob (handle=0 atteso)
        self.handshake(reinit=False)
        st72, ih = self.open72()
        if st72 != 0:
            ev("  open72(#1) status=0x%x" % st72); return 0, b"", st72
        c1, p1, _ = self.commit(ref20, register=False)
        ev("  commit#1 status=0x%x payload=%dB (blob atteso)" % (c1, len(p1)))
        # commit#2: sessione nuova, tail-registrazione -> handle
        self.handshake(reinit=False)
        st72, ih = self.open72()
        if st72 != 0:
            ev("  open72(#2) status=0x%x" % st72); return 0, b"", st72
        c2, p2, _ = self.commit(ref20, register=True)
        h, tid = self.parse_commit(p2)
        ev("  commit#2 status=0x%x payload=%dB handle=0x%x" % (c2, len(p2), h))
        return h, tid, c2

    def verify(self, handles, to=6000):
        """Match 1:N contro una lista di template handle (int o lista). Ritorna
        (status, result, match_id20, match_handle). result=1 MATCH, 0 NO-MATCH.
        Richiede una capture gia' fatta (dito acquisito nel buffer del chip)."""
        if isinstance(handles, int):
            handles = [handles]
        ih = struct.pack("<I", self.ihandle)
        harr = b"".join(struct.pack("<I", h) for h in handles)
        # formato verify 0x73: sess | 0x148 | 0x53e2 | 0 | [tag2, len, handle...] | [tag3, slot 20B]
        data = (bytes.fromhex("0000000004000000") + ih +
                bytes.fromhex("000000000400000048010000") +      # 0x148
                bytes.fromhex("00000000""04000000""e2530000") +  # 0x53e2
                bytes.fromhex("00000000""04000000""00000000") +  # 0
                struct.pack("<II", 2, len(harr)) + harr +        # tag2, N handle
                bytes.fromhex("03000000""14000000"))             # tag3, slot risultato 20B
        st, pl, _ = self.secure_cmd(0x02430073, data, to=to)
        # risposta: 0|len4|result(4)|0|len4|handle(4)|tag3|len0x14|match_id(20B)
        result = struct.unpack_from("<I", pl, 8)[0] if len(pl) >= 12 else -1
        mh = struct.unpack_from("<I", pl, 20)[0] if len(pl) >= 24 else 0
        mid = pl[32:52] if len(pl) >= 52 else pl[20:]
        return st, result, mid, mh

    def wait_finger(self, to=20000):
        """Attende l'evento interrupt EP 0x85 = 0300.... (dito giu'). True se rilevato."""
        t0 = time.time()
        while (time.time() - t0) * 1000 < to:
            try:
                n = bytes(self.d.dev.read(C.EP_INT, 16, timeout=1500))
            except Exception:
                continue
            if len(n) >= 1 and n[0] == 0x03:
                return True
        return False
