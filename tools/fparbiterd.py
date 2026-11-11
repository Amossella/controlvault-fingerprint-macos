#!/usr/local/bin/python3
"""FP Arbiter — UNICO proprietario del lettore ControlVault.

Tutti gli altri (demone sblocco, PAM/sudo, GUI FP Manager, enroll) NON aprono più
il lettore: chiedono a questo servizio via socket Unix. Ogni accesso al lettore è
SERIALIZZATO da un lock globale → mai due sessioni sicure in parallelo, che è la
causa dei blocchi "handshake 0B / lettore non pronto".

Protocollo: una riga JSON per richiesta, una riga JSON di risposta.
  {"cmd":"ping"}                      -> {"ok":true}
  {"cmd":"verify","timeout":25}       -> {"ok":true|false}        (match impronta)
  {"cmd":"enroll"}                    -> {"ok":true,"handle":N}   (registra, salva JSON)
  {"cmd":"remove","handle":N}         -> {"ok":true,"chip":bool}
  {"cmd":"list"}                      -> {"ok":true,"templates":[...]}
  {"cmd":"reset"}                     -> {"ok":true}              (reset USB)

Socket: ~/usbcfg/controlvault/arbiter.sock (0600, in una cartella dell'utente: altri
utenti non possono né collegarsi né crearne uno finto; root/PAM si collega lo stesso).
Log:    ~/usbcfg/controlvault/fparbiter.log
"""
import sys, os, json, time, socket, threading, traceback

TOOLS = "/Users/amoslobianco/usbcfg/tools"
CV = "/Users/amoslobianco/usbcfg/controlvault"
sys.path.insert(0, TOOLS)
sys.path.insert(0, CV)

SOCK_PATH = os.path.join(CV, "arbiter.sock")
TPL = os.path.join(CV, "mac_template.json")

_reader_lock = threading.Lock()   # serializza OGNI accesso al lettore


def log(m):
    # launchd reindirizza stderr su fparbiter.log: scrivere anche sul file
    # raddoppiava ogni riga.
    sys.stderr.write(time.strftime("%H:%M:%S ") + m + "\n"); sys.stderr.flush()


# ----------------------------- template JSON -----------------------------
def load_templates():
    try:
        return json.load(open(TPL)).get("templates", [])
    except Exception:
        return []


def save_templates(items):
    # scrittura atomica: un crash a metà non deve azzerare l'elenco delle impronte
    tmp = TPL + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"templates": items}, f, indent=2)
    os.replace(tmp, TPL)


def _handles():
    return [r["handle"] for r in load_templates() if r.get("handle")]


# ----------------------------- sessione lettore -----------------------------
def _begin_session(C, secure):
    """Claim + reset + handshake (NIENTE open: lo fa ogni operazione, perché enroll
    apre da sé → un pre-open causava doppia apertura e 0xf). Su 0B tenta reset USB."""
    try:
        d = C.ControlVault(); d.claim()
    except Exception as e:
        raise RuntimeError("claim fallito: %s" % e)
    try:
        s = secure.SecureSession(d); s.reset(); s.handshake()
        return d, s
    except Exception as e:
        # lettore impuntato (tipico "chiave pubblica non valida 0B"): reset e 1 retry
        log("handshake KO (%s) → reset USB e ritento" % e)
        try:
            d.dev.reset()
        except Exception as e2:
            log("reset USB non riuscito: %s" % e2)
        time.sleep(0.4)
        try:
            s = secure.SecureSession(d); s.reset(); s.handshake()
            return d, s
        except Exception as e3:
            try: d.release()
            except Exception: pass
            raise RuntimeError("handshake fallito anche dopo reset: %s" % e3)


# ----------------------------- operazioni -----------------------------
def op_verify(timeout=25.0):
    """Cattura + match impronta. Riprova entro la finestra sui tocchi non combacianti
    (max 5), così un appoggio storto non fa fallire subito."""
    handles = _handles()
    if not handles:
        return {"ok": False, "error": "nessun template registrato"}
    import controlvault as C, secure
    with _reader_lock:
        d = None
        try:
            d, s = _begin_session(C, secure)
            st, ih = s.open()
            if st != 0:
                return {"ok": False, "error": "open 0x%x" % st}
            t0 = time.time(); misses = 0
            while time.time() - t0 < timeout:
                stc, R, pl, notif = s.capture()
                if stc != 0:
                    for cw in (0x0440006d, 0x04400068):
                        try:
                            d.transact(C.build_envelope(cw, bytes.fromhex("000000000400000000000000"), counter=2))
                        except Exception:
                            pass
                    stc, R, pl, notif = s.capture()
                if stc != 0:
                    time.sleep(0.2); continue
                remaining = max(1.0, timeout - (time.time() - t0))
                if not s.wait_finger(to=int(remaining * 1000)):
                    break
                res = 0
                for _ in range(10):
                    st2, res, mid, mh = s.verify(handles)
                    if st2 not in (0x85, 0x0f):
                        break
                    time.sleep(0.2)
                if res == 1:
                    log("verify ok ✓")
                    return {"ok": True}
                misses += 1
                if misses >= 5:
                    log("verify: troppi tocchi non combacianti")
                    return {"ok": False, "error": "non riconosciuta"}
                time.sleep(0.3)
            return {"ok": False, "error": "timeout"}
        except Exception as e:
            log("verify errore: %s" % e)
            return {"ok": False, "error": str(e)}
        finally:
            try:
                if d: d.release()
            except Exception:
                pass


def op_enroll(on_event=None):
    def ev(m):
        if on_event:
            try: on_event(m)
            except Exception: pass
    import controlvault as C, secure
    with _reader_lock:
        d = None
        try:
            d, s = _begin_session(C, secure)
            ok, last, stages, cst, handle, tid = s.enroll(
                target_stages=8, max_stages=14, on_event=ev)
            if not ok or handle == 0:
                return {"ok": False, "error": "enroll fallito (status=0x%x stadi=%d)" % (last, stages)}
            rec = {"handle": handle, "id": tid.hex(), "stages": stages,
                   "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
            allrec = [t for t in load_templates() if t.get("handle") != handle]
            allrec.append(rec)
            save_templates(allrec)
            log("enroll ok handle=0x%x (totali=%d)" % (handle, len(allrec)))
            return {"ok": True, "handle": handle, "count": len(allrec)}
        except Exception as e:
            log("enroll errore: %s" % e)
            return {"ok": False, "error": str(e)}
        finally:
            try:
                if d: d.release()
            except Exception:
                pass


def op_remove(handle):
    import controlvault as C, secure
    chip_ok = None
    with _reader_lock:
        d = None
        try:
            if handle:
                d, s = _begin_session(C, secure)
                st, ih = s.open72()
                if st == 0:
                    st2, _ = s.delete_object(handle)
                    chip_ok = (st2 == 0)
                else:
                    chip_ok = False
        except Exception as e:
            log("remove errore: %s" % e); chip_ok = False
        finally:
            try:
                if d: d.release()
            except Exception:
                pass
    save_templates([x for x in load_templates() if x.get("handle") != handle])
    return {"ok": True, "chip": bool(chip_ok)}


def op_reset():
    import controlvault as C
    with _reader_lock:
        try:
            d = C.ControlVault(); d.claim()
            try:
                d.dev.reset()
            finally:
                try: d.release()
                except Exception: pass
            log("reset USB eseguito")
            return {"ok": True}
        except Exception as e:
            log("reset errore: %s" % e)
            return {"ok": False, "error": str(e)}


def handle_request(obj, send=None):
    cmd = (obj or {}).get("cmd")
    if cmd == "ping":
        return {"ok": True}
    if cmd == "verify":
        return op_verify(float(obj.get("timeout", 25.0)))
    if cmd == "enroll":
        # streaming: ogni stadio è inviato come {"event": ...}; la risposta finale
        # ha "ok". Così il client (CLI/GUI) mostra "appoggia il dito" in tempo reale.
        return op_enroll(on_event=(lambda m: send({"event": m})) if send else None)
    if cmd == "remove":
        return op_remove(obj.get("handle"))
    if cmd == "list":
        return {"ok": True, "templates": load_templates()}
    if cmd == "reset":
        return op_reset()
    return {"ok": False, "error": "comando sconosciuto: %r" % cmd}


# ----------------------------- server socket -----------------------------
def serve_conn(conn):
    try:
        conn.settimeout(120)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        line = buf.split(b"\n", 1)[0]
        try:
            obj = json.loads(line.decode("utf-8"))
        except Exception as e:
            conn.sendall((json.dumps({"ok": False, "error": "json: %s" % e}) + "\n").encode())
            return

        def send(o):
            conn.sendall((json.dumps(o) + "\n").encode())

        resp = handle_request(obj, send)   # può inviare eventi di streaming
        send(resp)                         # riga finale (contiene "ok")
    except Exception:
        log("conn errore:\n" + traceback.format_exc())
    finally:
        try: conn.close()
        except Exception: pass


def main():
    if os.path.exists(SOCK_PATH):
        try: os.unlink(SOCK_PATH)
        except Exception: pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o600)   # solo il proprietario (root/PAM entra comunque)
    srv.listen(8)
    log("FP Arbiter in ascolto su %s" % SOCK_PATH)
    while True:
        try:
            conn, _ = srv.accept()
        except Exception as e:
            log("accept errore: %s" % e); time.sleep(0.2); continue
        threading.Thread(target=serve_conn, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
