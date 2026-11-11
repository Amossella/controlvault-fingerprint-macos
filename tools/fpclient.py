#!/usr/local/bin/python3
"""Client dell'FP Arbiter (fparbiterd), l'unico processo che apre il lettore.
Lo usano demone, PAM/sudo, GUI e strumenti CLI.

API:
    available()                     -> bool   (l'arbitro risponde?)
    verify(timeout)                 -> bool   (match impronta)
    call(obj, wait=35)              -> dict   (richiesta con risposta singola)
    call_stream(obj, on_event, wait)-> dict   (richiesta con eventi, es. enroll)

Se l'arbitro NON è raggiungibile le chiamate ritornano
{"ok": False, "error": "no-arbiter"}.
"""
import json, os, socket, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvfp_config as cfg

SOCK_PATH = cfg.SOCK_PATH
NO_ARBITER = {"ok": False, "error": "no-arbiter"}


def _trusted():
    """Il socket deve appartenere al proprietario del progetto (o a root): chi
    risponde 'ok' a una verify autorizza sudo, quindi non ci si fida di altri."""
    try:
        return os.stat(SOCK_PATH).st_uid in (0, os.stat(cfg.TOOLS).st_uid)
    except OSError:
        return False


def _connect():
    if not _trusted():
        raise OSError("socket assente o non fidato")
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5.0)
    c.connect(SOCK_PATH)
    return c


def call_stream(obj, on_event=None, wait=120.0):
    """Invia una richiesta e legge le righe di risposta: quelle {"event": ...}
    vanno a on_event (es. 'appoggia il dito'), la riga finale (con 'ok') è il
    valore di ritorno."""
    try:
        c = _connect()
    except Exception:
        return dict(NO_ARBITER)
    try:
        c.settimeout(wait)
        c.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        f = c.makefile("r", encoding="utf-8")
        while True:
            line = f.readline()
            if not line:
                return {"ok": False, "error": "no-reply"}
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if "event" in msg and "ok" not in msg:
                if on_event:
                    try: on_event(msg["event"])
                    except Exception: pass
                continue
            return msg
    except Exception as e:
        return {"ok": False, "error": "client: %s" % e}
    finally:
        try: c.close()
        except Exception: pass


def call(obj, wait=35.0):
    return call_stream(obj, None, wait)


def available():
    return bool(call({"cmd": "ping"}, wait=3.0).get("ok"))


def verify(timeout=25.0):
    # il server può impiegare fino a 'timeout' (l'utente che appoggia il dito):
    # il client aspetta un po' di più.
    r = call({"cmd": "verify", "timeout": timeout}, wait=timeout + 10.0)
    return bool(r.get("ok"))
