#!/usr/local/bin/python3
"""Cancella un template dal chip (cv_delete_object) tramite l'arbitro.

USO:
  python3 tools/fpdelete.py --list          elenca gli handle salvati
  python3 tools/fpdelete.py <handle>        es. 0x96a4af (hex) oppure 9872047

La voce viene tolta anche da mac_template.json, quindi non vale più per sudo e
sblocco. Richiede il servizio fparbiterd attivo.
"""
import sys, os, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpclient


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("handle", nargs="?", help="handle del template (0x.. o decimale)")
    ap.add_argument("--list", action="store_true", help="elenca gli handle salvati")
    a = ap.parse_args(argv)

    if not fpclient.available():
        print("Servizio impronte (fparbiterd) non attivo.")
        return 1

    if a.list or not a.handle:
        items = fpclient.call({"cmd": "list"}).get("templates", [])
        if not items:
            print("Nessuna impronta registrata.")
        for t in items:
            print("  %-20s handle=0x%x (%d)  id=%s" %
                  (t.get("name", "?"), t.get("handle", 0), t.get("handle", 0), t.get("id", "")))
        if not a.handle:
            return 0

    h = int(a.handle, 0)
    print("Cancellazione del template handle=0x%x ..." % h)
    r = fpclient.call({"cmd": "remove", "handle": h}, wait=40.0)
    if not r.get("ok"):
        print("❌ Errore: %s" % r.get("error"))
        return 1
    if r.get("chip"):
        print("✅ Cancellata dal chip e scollegata.")
    else:
        print("⚠️  Scollegata da sudo/sblocco, ma il chip non ha confermato la cancellazione.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
