#!/usr/local/bin/python3
"""Registra un'impronta NATIVAMENTE su macOS (enroll cifrato) e salva l'handle del template.

Avvio:
    /usr/local/bin/python3 ~/usbcfg/tools/fpenroll.py

Appoggia e solleva lo STESSO dito quando te lo chiede (4 volte). Alla fine salva
l'handle del template in ~/usbcfg/controlvault/mac_template.json, che fpverify.py usera'
per il match. Nessuna dipendenza da Windows.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.expanduser("~/usbcfg/controlvault"))
import controlvault as C
import secure

OUT = os.path.expanduser("~/usbcfg/controlvault/mac_template.json")
GREEN = "\033[92m"; RED = "\033[91m"; YEL = "\033[93m"; RST = "\033[0m"


def main():
    d = C.ControlVault(); d.claim()
    print("Connessione al lettore...", flush=True)
    try:
        s = secure.SecureSession(d)
        s.reset(); s.handshake()
        print(GREEN + "Pronto per la registrazione." + RST +
              " Appoggia e solleva lo STESSO dito quando vedi >> (4 volte).\n", flush=True)
        ok, last, stages, cst, handle, tid = s.enroll(target_stages=8, max_stages=14)
        print()
        if not ok or handle == 0:
            print(RED + "Registrazione FALLITA" + RST +
                  " (status=0x%x, commit=0x%x, stadi=%d, handle=0x%x)" %
                  (last, cst or 0, stages, handle))
            print("Riprova: solleva bene il dito tra un tocco e l'altro.")
            return
        rec = {"handle": handle, "id": tid.hex(), "stages": stages,
               "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        # supporta piu' impronte: accumula in una lista
        allrec = []
        if os.path.exists(OUT):
            try:
                old = json.load(open(OUT))
                allrec = old.get("templates", [])
            except Exception:
                pass
        allrec = [t for t in allrec if t.get("handle") != handle]
        allrec.append(rec)
        json.dump({"templates": allrec}, open(OUT, "w"), indent=2)
        print(GREEN + "✅ REGISTRATA su macOS." + RST)
        print("   handle template = 0x%x" % handle)
        print("   id              = %s" % tid.hex())
        print("   salvato in       %s  (%d impronta/e totali)" % (OUT, len(allrec)))
        print("\nOra lancia  fpverify.py  e prova il dito.")
    except KeyboardInterrupt:
        print("\nInterrotto.")
    finally:
        d.release()


if __name__ == "__main__":
    main()
