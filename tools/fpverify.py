#!/usr/local/bin/python3
"""Verifica impronta (match on-chip) — loop interattivo tramite l'arbitro.

Avvio:
    python3 tools/fpverify.py

A ogni tocco stampa MATCH / NO MATCH. Ctrl+C per uscire.
Richiede il servizio fparbiterd attivo.
"""
import sys, os, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpclient

GREEN = "\033[92m"; RED = "\033[91m"; YEL = "\033[93m"; RST = "\033[0m"


def main():
    if not fpclient.available():
        print(RED + "Servizio impronte (fparbiterd) non attivo." + RST)
        return 1
    n = len(fpclient.call({"cmd": "list"}).get("templates", []))
    print("Impronte registrate: %d" % n)
    print(GREEN + "Pronto." + RST + " Appoggia un dito (Ctrl+C per uscire).\n", flush=True)
    i = 0
    try:
        while True:
            r = fpclient.call({"cmd": "verify", "timeout": 30.0}, wait=40.0)
            err = r.get("error")
            if err == "timeout":
                continue                      # nessun dito: resta in attesa
            i += 1
            ts = time.strftime("%H:%M:%S")
            if r.get("ok"):
                print("%s  #%d  %s✅ MATCH%s" % (ts, i, GREEN, RST), flush=True)
            elif err == "non riconosciuta":
                print("%s  #%d  %s❌ NO MATCH%s" % (ts, i, RED, RST), flush=True)
            else:
                print("%s  #%d  %s? %s%s" % (ts, i, YEL, err, RST), flush=True)
                time.sleep(1.0)
            time.sleep(0.8)
    except KeyboardInterrupt:
        print("\nUscita.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
