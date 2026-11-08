#!/usr/local/bin/python3
"""Diagnostica IDENTIFY 1:N: appoggia un dito e prova a far restituire al chip
l'handle del template che combacia, SENZA sapere l'handle in anticipo.

Prova in sequenza, sullo stesso tocco non e' possibile (la capture si consuma),
quindi ad ogni tocco prova UNA variante; ripeti appoggiando il dito piu' volte.

Avvio:
    /usr/local/bin/python3 ~/usbcfg/tools/fpident.py
Ctrl+C per uscire.
"""
import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.expanduser("~/usbcfg/controlvault"))
import controlvault as C
import secure


def build_identify(s, mode):
    ih = struct.pack("<I", s.ihandle)
    base = (bytes.fromhex("0000000004000000") + ih +
            bytes.fromhex("000000000400000048010000") +      # 0x148
            bytes.fromhex("00000000""04000000""e2530000") +  # 0x53e2
            bytes.fromhex("00000000""04000000""00000000"))   # 0
    slot = bytes.fromhex("03000000""14000000")               # tag3 slot 20B
    if mode == "empty":        # array handle vuoto
        return base + struct.pack("<II", 2, 0) + slot
    if mode == "nohandle":     # proprio senza campo array
        return base + slot
    if mode == "zero":         # un handle = 0
        return base + struct.pack("<III", 2, 4, 0) + slot
    if mode == "ff":           # handle = 0xffffffff (wildcard)
        return base + struct.pack("<II", 2, 4) + b"\xff\xff\xff\xff" + slot
    return base + slot


def dump(tag, st, pl):
    print("  [%-8s] status=0x%x  resp=%dB" % (tag, st, len(pl)))
    for off in range(0, min(len(pl), 64), 16):
        print("    %04x  %s" % (off, pl[off:off + 16].hex(' ')))
    if len(pl) >= 20:
        res = struct.unpack_from("<I", pl, 8)[0]
        mh = struct.unpack_from("<I", pl, 16)[0]
        print("    -> result=%d  match_handle=0x%x" % (res, mh))


def unstick(s):
    for cw in (0x0440006d, 0x04400068):
        try:
            s.d.transact(C.build_envelope(cw, bytes.fromhex("000000000400000000000000"), counter=2))
        except Exception:
            pass


MODES = ["empty", "nohandle", "zero", "ff"]


def main():
    d = C.ControlVault(); d.claim()
    print("Connessione...", flush=True)
    try:
        s = secure.SecureSession(d)
        s.reset(); s.handshake()
        st, ih = s.open()
        print("open=0x%x ihandle=0x%x\nAppoggia il dito registrato; provo le varianti identify.\n" % (st, ih), flush=True)
        i = 0
        while True:
            mode = MODES[i % len(MODES)]; i += 1
            st, R, pl, notif = s.capture()
            if st != 0:
                unstick(s); st, R, pl, notif = s.capture()
            if st != 0:
                time.sleep(0.2); continue
            print(">> APPOGGIA IL DITO (variante: %s)" % mode, flush=True)
            if not s.wait_finger(to=60000):
                continue
            data = build_identify(s, mode)
            stx, plx = 0x85, b""
            for _ in range(8):
                stx, plx, _ = s.secure_cmd(0x02430073, data)
                if stx not in (0x85, 0x0f):
                    break
                time.sleep(0.2)
            dump(mode, stx, plx)
            print(flush=True)
            time.sleep(0.8)
    except KeyboardInterrupt:
        print("\nUscita.")
    finally:
        d.release()


if __name__ == "__main__":
    main()
