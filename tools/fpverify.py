#!/usr/local/bin/python3
"""Verifica impronta ControlVault (match on-chip) — loop interattivo.

Avvio:
    /usr/local/bin/python3 ~/usbcfg/tools/fpverify.py

Usa gli handle dei template REGISTRATI SU macOS (~/usbcfg/controlvault/mac_template.json,
creato da fpenroll.py). Se quel file non c'e', ripiega sull'handle del template Windows
(0x5dc14c) per compatibilita'.

Gira in continuo: ogni volta che APPOGGI un dito stampa una riga MATCH / NO-MATCH.
Ctrl+C per uscire.
"""
import sys, os, json, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.expanduser("~/usbcfg/controlvault"))
import controlvault as C
import secure

TPL = os.path.expanduser("~/usbcfg/controlvault/mac_template.json")
WIN_FALLBACK = [0x5dc14c]
GREEN = "\033[92m"; RED = "\033[91m"; YEL = "\033[93m"; RST = "\033[0m"


def load_handles():
    if os.path.exists(TPL):
        try:
            recs = json.load(open(TPL)).get("templates", [])
            hs = [r["handle"] for r in recs if r.get("handle")]
            if hs:
                return hs, False
        except Exception:
            pass
    return WIN_FALLBACK, True


def unstick(s):
    for cw in (0x0440006d, 0x04400068):   # discard + capture-wait in chiaro
        try:
            s.d.transact(C.build_envelope(cw, bytes.fromhex("000000000400000000000000"), counter=2))
        except Exception:
            pass


def one_match(s, handles):
    st, R, pl, notif = s.capture()
    if st != 0:
        unstick(s); st, R, pl, notif = s.capture()
    if st != 0:
        return None
    if not s.wait_finger(to=60000):
        return None
    st = 0x85
    for _ in range(10):
        st, result, mid, mh = s.verify(handles)
        if st not in (0x85, 0x0f):
            break
        time.sleep(0.2)
    return (st, result, mid.hex(), mh)


def main():
    handles, fb = load_handles()
    d = C.ControlVault(); d.claim()
    print("Connessione al lettore...", flush=True)
    try:
        s = secure.SecureSession(d)
        s.reset(); s.handshake()
        st, ih = s.open()
        if st != 0:
            print("Errore open: 0x%x" % st); return
        src = (YEL + "Windows (fallback)" + RST) if fb else (GREEN + "macOS" + RST)
        print("Template: %s  handle(s)=%s" % (src, ", ".join("0x%x" % h for h in handles)))
        print(GREEN + "Pronto." + RST + " Appoggia un dito (Ctrl+C per uscire).\n", flush=True)
        n = 0
        while True:
            r = one_match(s, handles)
            if r is None:
                unstick(s); time.sleep(0.3); continue
            n += 1
            st, result, mid, mh = r
            ts = time.strftime("%H:%M:%S")
            if result == 1:
                print("%s  #%d  %s✅ MATCH%s   handle=0x%x  (status=0x%x)  id=%s" %
                      (ts, n, GREEN, RST, mh, st, mid[:16]), flush=True)
            elif result == 0:
                print("%s  #%d  %s❌ NO MATCH%s   (status=0x%x)" % (ts, n, RED, RST, st), flush=True)
            else:
                print("%s  #%d  %s? status=0x%x result=%d%s" % (ts, n, YEL, st, result, RST), flush=True)
            time.sleep(0.8)
    except KeyboardInterrupt:
        print("\nUscita.")
    finally:
        d.release()


if __name__ == "__main__":
    main()
