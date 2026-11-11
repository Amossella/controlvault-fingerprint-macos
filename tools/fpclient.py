#!/usr/local/bin/python3
"""Client dell'FP Arbiter (fparbiterd). Lo usano demone, PAM/sudo e GUI al posto
di aprire il lettore: così c'è un solo proprietario del ControlVault.

API:
    available()            -> bool    (l'arbitro risponde?)
    verify(timeout=25)     -> bool    (match impronta)
    call(obj, wait=35)     -> dict    (richiesta generica)

Se l'arbitro NON è raggiungibile, call() ritorna {"ok":False,"error":"no-arbiter"}
così il chiamante può decidere un fallback.
"""
import json, socket

SOCK_PATH = "/tmp/cvfp-arbiter.sock"


def call(obj, wait=35.0):
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(5.0)
        c.connect(SOCK_PATH)
    except Exception:
        return {"ok": False, "error": "no-arbiter"}
    try:
        c.settimeout(wait)
        c.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = c.recv(4096)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return {"ok": False, "error": "no-reply"}
        return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    except Exception as e:
        return {"ok": False, "error": "client: %s" % e}
    finally:
        try: c.close()
        except Exception: pass


def available():
    return call({"cmd": "ping"}, wait=3.0).get("ok", False)


def verify(timeout=25.0):
    # il server può impiegare fino a 'timeout' (l'utente che appoggia il dito):
    # il client aspetta un po' di più.
    r = call({"cmd": "verify", "timeout": timeout}, wait=timeout + 10.0)
    return bool(r.get("ok"))
