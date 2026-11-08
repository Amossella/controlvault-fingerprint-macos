"""
controlvault.py — driver utente (prototipo) per Dell ControlVault2 / Broadcom BCM5880
(USB 0a5c:5834) su macOS, costruito per reverse engineering del driver Dell Linux
(libfprint-2-tod-1-broadcom.so) e dalle catture USBPcap.

STATO (2026-11-07):
  FUNZIONANTE e verificato sul device:
    - trasporto libusb (bulk OUT 0x01 / interrupt IN 0x85 / bulk IN 0x81)
    - envelope + encoder parametri/blob (riproduce l'init catturato byte per byte)
    - init (cmd 0x82) e cv_open (cmd 0x23): entrambi status 0 sul device
  SPERIMENTALE (status 0 ma effetto fisico NON confermato):
    - enable_fingerprint con cmd_word 0x00400041 -> status 0 (b2 con bit0=1 -> status 15).
      Nessun dato in risposta; serve osservare il sensore per confermare l'abilitazione.
  DA COMPLETARE (porting del driver host Dell):
    - cmd_word generico di identify/enroll (bit-packing in cvhEncapsulateCmd @0x1ee80)
    - tabella sessioni host (GetCVInternalHandle) ed eventuale autorizzazione
    - parametri dallo strato libfprint; sequenza enroll; integrazione PAM

Prerequisito di sistema: il kext usbcfgfix v6 deve forzare SET_CONFIGURATION(0)
(il device espone bConfigurationValue=0). Senza, i bulk falliscono (transaction error).

Dipendenze: pyusb + libusb (libusb_package).
"""
import struct
import usb.core
import usb.util
import usb.backend.libusb1
import libusb_package

VID, PID = 0x0a5c, 0x5834
EP_OUT, EP_IN, EP_INT = 0x01, 0x81, 0x85

# encapsulation types (Talos: CV_ENCAP_*) — confermati in InitParam_List @0xe0b0
ENCAP_STRUC = 0
ENCAP_LENVAL_STRUC = 1
ENCAP_LENVAL_PAIR = 2
ENCAP_INOUT = 3

# command word byte0 (opcode) ricavati dai builder / dispatch del driver
CMD_INIT = 0x00400082          # init (verificato: wire completo dalle catture)
CMD_GET_CV_PUBKEY = 0x00410023 # cv_open / GetCVPublicKeyCmd (verificato)
# opcode dei verbi generici (byte0); il cmd_word completo lo compone cvhManageCVAPICall
OP_ENABLE_FP = 0x41            # cv_enable_fingerprint
OP_IDENTIFY = 0x35            # cv_identify_user
OP_ENROLL_STARTED = 0x8a       # cv_cmd_enrollment_started
OP_CAPTURE = 0x5c             # cv_fingerprint_capture (encap 2, 5 param)
OP_CAPTURE_START = 0x66        # cv_fingerprint_capture_start (encap 1, 3 param)
OP_CAPTURE_WAIT = 0x68        # cv_fingerprint_capture_wait
OP_CAPTURE_RESULT = 0x69       # cv_fingerprint_capture_get_result
OP_ENABLE_WBDI = 0x63         # cv_enable_wbdi (abilitazione biometrica REALE, da cvif_dev_enable)
OP_ENABLE_SMARTCARD = 0x40     # cv_enable_smartcard

# cmd_word completo = opcode | (0x40 << 16)  [byte categoria base 0x40, verificato su device]
def cmdword(opcode):
    return opcode | (0x40 << 16)

# codici di stato osservati sul device (envelope offset 20)
STATUS = {
    0: "OK",
    0x0f: "categoria cmd errata (b2 dispari)",
    0x85: "attesa dito (riprova capture_start)",
    0x86: "sensore in inizializzazione/arming (riprova)",
    0x89: "nessun risultato disponibile",
}
# Notifica interrupt EP 0x85 = 0300000000000000 => evento dito/scansione
# (nelle catture Windows precede il comando di lettura della scansione).
NOTIFY_FINGER = bytes.fromhex("0300000000000000")


def u32(v):
    return struct.pack("<I", v)


def param(encap_type, value=b""):
    """Un parametro come lo costruisce InitParam_List: [type:4][len:4][value]."""
    if encap_type == ENCAP_INOUT:
        return struct.pack("<II", encap_type, len(value))
    return struct.pack("<II", encap_type, len(value)) + value


def build_blob(params):
    """Blob dati come ConstructBlob @0xf070: concat dei parametri, value padded a 4B."""
    out = b""
    for encap_type, value in params:
        out += struct.pack("<II", encap_type, len(value))
        if encap_type != ENCAP_INOUT:
            out += value + b"\x00" * ((-len(value)) % 4)
    return out


def build_envelope(cmd_word, data=b"", seq=1, counter=1, handle=0, status=0):
    """Envelope sul filo (confermato dalle catture)."""
    body = struct.pack("<IIIIII", seq, 0, cmd_word, counter, handle, status)
    body += b"\x00" * 16
    body += struct.pack("<I", len(data)) + data
    total = len(body)
    return body[:4] + struct.pack("<I", total) + body[8:]


def parse_envelope(resp):
    seq, total, cmd, counter, handle, status = struct.unpack_from("<IIIIII", resp, 0)
    dlen = struct.unpack_from("<I", resp, 40)[0] if len(resp) >= 44 else 0
    return {
        "seq": seq, "cmd": cmd, "counter": counter, "handle": handle,
        "status": status, "data": resp[44:44 + dlen],
    }


class ControlVault:
    def __init__(self):
        be = usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
        self.dev = usb.core.find(idVendor=VID, idProduct=PID, backend=be)
        if self.dev is None:
            raise RuntimeError("device 0a5c:5834 non trovato")
        self.handle = 0
        self._claimed = False
        self._lockfd = None

    # lock condiviso: un solo processo (FP Manager, demone, CLI) usa il lettore per volta.
    # flock si rilascia da solo se il processo muore -> niente blocchi "fantasma".
    _LOCK_PATH = "/tmp/cv-fp-reader.lock"

    def _unlock(self):
        import fcntl, os
        if self._lockfd is not None:
            try: fcntl.flock(self._lockfd, fcntl.LOCK_UN)
            except Exception: pass
            try: os.close(self._lockfd)
            except Exception: pass
            self._lockfd = None

    def claim(self, wait=4.0):
        import fcntl, os, time
        fd = os.open(self._LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o666)
        try: os.fchmod(fd, 0o666)
        except Exception: pass
        deadline = time.time() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.time() >= deadline:
                    try: os.close(fd)
                    except Exception: pass
                    raise RuntimeError("lettore occupato da un altro processo "
                                       "(demone di sblocco o FP Manager). Riprova tra un attimo.")
                time.sleep(0.2)
        self._lockfd = fd
        try:
            usb.util.claim_interface(self.dev, 0)
        except Exception:
            self._unlock()
            raise
        self._claimed = True

    def release(self):
        if self._claimed:
            usb.util.release_interface(self.dev, 0)
            self._claimed = False
        self._unlock()

    def active_config(self):
        return bytes(self.dev.ctrl_transfer(0x80, 8, 0, 0, 1, 1000))[0]

    def transact(self, pkt, timeout=5000):
        """Invia un envelope e legge notifica (interrupt) + risposta (bulk)."""
        self.dev.write(EP_OUT, pkt, timeout=timeout)
        try:
            notif = bytes(self.dev.read(EP_INT, 16, timeout=timeout))
        except usb.core.USBError:
            notif = b""
        rlen = struct.unpack_from("<I", notif, 4)[0] if len(notif) >= 8 else 512
        resp = bytes(self.dev.read(EP_IN, max(rlen, 64), timeout=timeout))
        return parse_envelope(resp)

    # --- comandi verificati ---
    def init(self):
        data = build_blob([(ENCAP_STRUC, u32(0))])
        return self.transact(build_envelope(CMD_INIT, data, counter=1))

    def open_session(self, nonce=None):
        import os
        if nonce is None:
            nonce = os.urandom(20) + b"\x00\x00\x00\x00"
        r = self.transact(build_envelope(CMD_GET_CV_PUBKEY, nonce, counter=2))
        if r["status"] == 0:
            self.handle = r["handle"]
        return r

    # --- enable REALE (sequenza di cvif_dev_enable) ---
    def enable_wbdi(self, enable=1):
        """Abilitazione biometrica reale (cv_enable_wbdi 0x63). cvif_dev_enable chiama
        enable_smartcard + enable_wbdi + enable_radio. Con questo la macchina a stati
        della cattura si ARMA (capture_start passa da 0x86 a 0x0)."""
        data = build_blob([(ENCAP_STRUC, u32(self.handle)), (ENCAP_STRUC, u32(enable))])
        return self.transact(build_envelope(cmdword(OP_ENABLE_WBDI), data, counter=2, handle=self.handle))

    def capture_arm(self, tries=10):
        """Ripete capture_start finché status 0 (armato). 0x86=init, 0x85=attesa, 0=armato."""
        import time
        for _ in range(tries):
            r = self.capture_start()
            if r["status"] == 0:
                return r
            time.sleep(1.0)
        return r

    # --- verbi sperimentali (cmd_word parzialmente decodificato) ---
    def enable_fingerprint(self, enable=1, cmd_word=0x00400041, p0=None):
        """SPERIMENTALE. cvhEncapsulateCmd: cmd_word b0,b1=opcode (0x41),
        b2 base 0x40, bit request azzerato. Param: [internalHandle][enable].
        Da confermare osservando il sensore. p0 default = handle di sessione."""
        if p0 is None:
            p0 = self.handle
        data = build_blob([(ENCAP_STRUC, u32(p0)), (ENCAP_STRUC, u32(enable))])
        return self.transact(build_envelope(cmd_word, data, counter=2, handle=self.handle))

    def capture_start(self, params=None):
        """SPERIMENTALE. Avvia una cattura (opcode 0x66). Sul device:
        primo invio -> status 0 + 28 byte (token sessione cattura), poi 0x85 (pending).
        NOTA: con parametri segnaposto la cattura NON si arma (get_result resta 0x89).
        Servono i 3 parametri reali dallo strato libfprint."""
        if params is None:
            params = [(ENCAP_STRUC, u32(self.handle)),
                      (ENCAP_LENVAL_PAIR, b"\x00" * 4), (ENCAP_INOUT, b"")]
        return self.transact(build_envelope(cmdword(OP_CAPTURE_START), build_blob(params),
                                            counter=2, handle=self.handle))

    def capture_get_result(self):
        params = [(ENCAP_STRUC, u32(self.handle)), (ENCAP_INOUT, b"")]
        return self.transact(build_envelope(cmdword(OP_CAPTURE_RESULT), build_blob(params),
                                            counter=2, handle=self.handle))

    def identify(self):
        raise NotImplementedError("richiede sessione autorizzata + template registrati")

    def enroll(self):
        raise NotImplementedError("richiede enable + sequenza create_feature_set/commit")


if __name__ == "__main__":
    cv = ControlVault()
    cv.claim()
    try:
        print("config attiva:", cv.active_config())
        r = cv.init()
        print("init     -> status=%d cmd=%08x" % (r["status"], r["cmd"]))
        r = cv.open_session()
        print("open     -> status=%d handle=%08x cert=%s..." % (
            r["status"], r["handle"], r["data"][:16].hex()))
    finally:
        cv.release()
