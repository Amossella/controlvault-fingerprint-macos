#!/usr/local/bin/python3
"""Test SICURO della cancellazione di un template dal chip (cv_delete_object).

USO:
  /usr/local/bin/python3 fpdelete.py <handle>
  es.  fpdelete.py 0x96a4af       (hex)   oppure   fpdelete.py 9872047  (decimale)
  --list   mostra gli handle salvati in mac_template.json

⚠️  Provalo PRIMA su un dito "usa e getta" (registrane uno apposta con FP Manager,
    poi cancellalo con questo tool e verifica che non venga piu' riconosciuto,
    mentre il dito buono continua a funzionare).
"""
import sys, os, json, argparse
TOOLS = "/Users/amoslobianco/usbcfg/tools"
CV = "/Users/amoslobianco/usbcfg/controlvault"
sys.path.insert(0, CV); sys.path.insert(0, TOOLS)
import controlvault as C
import secure

TPL = os.path.join(CV, "mac_template.json")


def load():
    try:
        return json.load(open(TPL)).get("templates", [])
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("handle", nargs="?", help="handle del template (0x.. o decimale)")
    ap.add_argument("--list", action="store_true", help="elenca gli handle salvati")
    a = ap.parse_args()

    if a.list or not a.handle:
        items = load()
        if not items:
            print("Nessun template in mac_template.json")
        for t in items:
            print("  %-20s handle=0x%x (%d)  id=%s" %
                  (t.get("name", "?"), t.get("handle", 0), t.get("handle", 0), t.get("id", "")))
        if not a.handle:
            return

    h = int(a.handle, 0)
    print("Cancellazione del template handle=0x%x ..." % h)
    d = C.ControlVault(); d.claim()
    try:
        s = secure.SecureSession(d); s.reset(); s.handshake()
        st, ih = s.open72()
        print("  open72 -> status=0x%x  ihandle=0x%x" % (st, ih))
        if st != 0:
            print("  open fallita, annullo."); return
        st2, pl = s.delete_object(h)
        print("  delete -> status=0x%x" % st2)
        print("  payload:", pl.hex() if pl else "(vuoto)")
        if st2 == 0:
            print("✅ Il chip ha accettato la cancellazione (status 0).")
            print("   Verifica con fpverify.py che quel dito NON sia piu' riconosciuto.")
        else:
            print("❌ Il chip ha rifiutato (status 0x%x) — niente cancellato." % st2)
    finally:
        d.release()


if __name__ == "__main__":
    main()
