#!/usr/local/bin/python3
"""Autenticazione impronta single-shot per PAM.

Esce 0 se il dito appoggiato COMBACIA con un template registrato su macOS
(~/usbcfg/controlvault/mac_template.json), 1 altrimenti (timeout, nessun match, errore).
Pensato per essere lanciato dal modulo PAM pam_cvfp durante `sudo`.

Messaggi su stderr (visibili nel prompt sudo). Nessun output su stdout.

Uso:   /usr/local/bin/python3 fpauth.py [--timeout SEC] [--user NOME]
"""
import sys, os, json, time, argparse

# percorsi assoluti (il modulo PAM gira come root, cwd ignota)
TOOLS = "/Users/amoslobianco/usbcfg/tools"
CV = "/Users/amoslobianco/usbcfg/controlvault"
sys.path.insert(0, TOOLS)
sys.path.insert(0, CV)
TPL = os.path.join(CV, "mac_template.json")


def log(m):
    sys.stderr.write(m + "\n"); sys.stderr.flush()


def load_handles():
    try:
        recs = json.load(open(TPL)).get("templates", [])
        return [r["handle"] for r in recs if r.get("handle")]
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--user", default="")
    args = ap.parse_args()

    # Arbitro unico: se il servizio fparbiterd è attivo, NON apriamo il lettore
    # qui — glielo chiediamo (evita contese/0B col demone e la GUI).
    try:
        import fpclient
        if fpclient.available():
            ok = fpclient.verify(args.timeout)
            log("[impronta] " + ("riconosciuta ✓" if ok
                                  else "non riconosciuta — uso la password"))
            return 0 if ok else 1
    except Exception:
        pass   # arbitro non disponibile → fallback diretto qui sotto

    handles = load_handles()
    if not handles:
        log("[impronta] nessun template registrato — uso la password")
        return 1

    try:
        import controlvault as C
        import secure
    except Exception as e:
        log("[impronta] moduli non disponibili (%s) — uso la password" % e)
        return 1

    d = None
    try:
        d = C.ControlVault(); d.claim()
        s = secure.SecureSession(d)
        s.reset(); s.handshake()
        st, ih = s.open()
        if st != 0:
            log("[impronta] lettore non pronto — uso la password"); return 1
        log("[impronta] appoggia il dito sul sensore...")
        t0 = time.time()
        while time.time() - t0 < args.timeout:
            stc, R, pl, notif = s.capture()
            if stc != 0:
                # sblocca stato e riprova
                for cw in (0x0440006d, 0x04400068):
                    try:
                        d.transact(C.build_envelope(cw, bytes.fromhex("000000000400000000000000"), counter=2))
                    except Exception:
                        pass
                stc, R, pl, notif = s.capture()
            if stc != 0:
                time.sleep(0.2); continue
            remaining = max(1.0, args.timeout - (time.time() - t0))
            if not s.wait_finger(to=int(remaining * 1000)):
                break
            st2 = 0x85
            for _ in range(10):
                st2, result, mid, mh = s.verify(handles)
                if st2 not in (0x85, 0x0f):
                    break
                time.sleep(0.2)
            if result == 1:
                log("[impronta] riconosciuta ✓")
                return 0
            else:
                log("[impronta] non riconosciuta — uso la password")
                return 1
        log("[impronta] tempo scaduto — uso la password")
        return 1
    except Exception as e:
        log("[impronta] errore (%s) — uso la password" % e)
        return 1
    finally:
        try:
            if d: d.release()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
