#!/usr/local/bin/python3
"""Registra un'impronta su macOS (enroll cifrato) tramite l'arbitro.

Avvio:
    python3 tools/fpenroll.py [nome]

Appoggia e solleva lo STESSO dito a ogni richiesta (8 volte, variando un po'
l'appoggio). L'handle del template viene salvato in controlvault/mac_template.json.
Richiede il servizio fparbiterd attivo (lo installa install_unlock_agent.sh).
"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpclient

GREEN = "\033[92m"; RED = "\033[91m"; RST = "\033[0m"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    name = argv[0] if argv else None
    if not fpclient.available():
        print(RED + "Servizio impronte (fparbiterd) non attivo." + RST +
              " Avvialo con: bash tools/install_unlock_agent.sh")
        return 1
    print("Registrazione: appoggia e solleva lo STESSO dito a ogni richiesta.\n", flush=True)
    req = {"cmd": "enroll"}
    if name:
        req["name"] = name
    r = fpclient.call_stream(req, on_event=lambda m: print(m, flush=True), wait=180.0)
    if r.get("ok"):
        print(GREEN + "\n✅ REGISTRATA." + RST +
              " handle=0x%x  (%d impronta/e totali)" % (r.get("handle", 0), r.get("count", 0)))
        return 0
    print(RED + "\nRegistrazione FALLITA" + RST + ": %s" % r.get("error"))
    print("Riprova: solleva bene il dito tra un tocco e l'altro.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
