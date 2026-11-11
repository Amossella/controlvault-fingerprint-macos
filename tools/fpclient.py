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
import json, os, socket

_HERE = os.path.dirname(os.path.abspath(__file__))
SOCK_PATH = os.path.join(os.path.dirname(_HERE), "controlvault", "arbiter.sock")


def _trusted():
    """Il socket deve appartenere al proprietario del progetto (o a root): chi
    risponde 'ok' a una verify autorizza sudo, quindi non ci si fida di altri."""
    try:
        return os.stat(SOCK_PATH).st_uid in (0, os.stat(_HERE).st_uid)
    except OSError:
        return False


def _connect():
    if not _trusted():
        raise OSError("socket assente o non fidato")
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5.0)
    c.connect(SOCK_PATH)
    return c


def call(obj, wait=35.0):
    try:
        c = _connect()
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


def call_stream(obj, on_event=None, wait=120.0):
    """Come call(), ma legge PIÙ righe: le righe {"event": ...} vengono passate a
    on_event (es. 'appoggia il dito'), e si ritorna la riga finale (con 'ok').
    Usato per l'enroll, che altrimenti non darebbe feedback in tempo reale."""
    try:
        c = _connect()
    except Exception:
        return {"ok": False, "error": "no-arbiter"}
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


def available():
    return call({"cmd": "ping"}, wait=3.0).get("ok", False)


def verify(timeout=25.0):
    # il server può impiegare fino a 'timeout' (l'utente che appoggia il dito):
    # il client aspetta un po' di più.
    r = call({"cmd": "verify", "timeout": timeout}, wait=timeout + 10.0)
    return bool(r.get("ok"))
