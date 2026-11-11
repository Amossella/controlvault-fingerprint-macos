#!/usr/local/bin/python3
"""Autenticazione impronta single-shot per PAM (sudo).

Esce 0 se il dito appoggiato combacia con un'impronta registrata, 1 altrimenti
(timeout, nessun match, servizio non attivo). Lanciato da pam_cvfp durante `sudo`.

Non apre il lettore: chiede la verifica all'arbitro (fparbiterd). Se l'arbitro
non è attivo esce 1 e sudo prosegue con la password.

Messaggi su stderr (visibili nel prompt sudo). Nessun output su stdout.

Uso:   python3 fpauth.py [--timeout SEC] [--user NOME]
"""
import sys, os, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvfp_config as cfg
import fpclient

MESSAGES = {
    "timeout": "tempo scaduto",
    "non riconosciuta": "non riconosciuta",
    "nessun template registrato": "nessuna impronta registrata",
    "no-arbiter": "servizio impronte non attivo",
}


def log(m):
    sys.stderr.write(m + "\n"); sys.stderr.flush()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=cfg.SUDO_TIMEOUT)
    ap.add_argument("--user", default="")
    args = ap.parse_args(argv)

    if not fpclient.available():
        log("[impronta] servizio impronte non attivo — uso la password")
        return 1
    log("[impronta] appoggia il dito sul sensore...")
    r = fpclient.call({"cmd": "verify", "timeout": args.timeout}, wait=args.timeout + 10.0)
    if r.get("ok"):
        log("[impronta] riconosciuta ✓")
        return 0
    err = r.get("error") or "errore"
    log("[impronta] %s — uso la password" % MESSAGES.get(err, "lettore non pronto (%s)" % err))
    return 1


if __name__ == "__main__":
    sys.exit(main())
