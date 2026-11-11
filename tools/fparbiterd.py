#!/usr/local/bin/python3
"""FP Arbiter — UNICO proprietario del lettore ControlVault.

Demone di sblocco, PAM/sudo, GUI FP Manager e strumenti CLI NON aprono il lettore:
chiedono a questo servizio via socket Unix. Ogni accesso è SERIALIZZATO da un
lock → mai due sessioni sicure in parallelo (causa dei blocchi "handshake 0B").

La sessione col lettore (handshake + open) resta APERTA tra una verifica e
l'altra per SESSION_IDLE_TTL secondi: le verifiche successive partono subito,
senza rifare l'handshake. Se la sessione riusata risulta scaduta lato chip (o il
lettore è stato scollegato, es. dopo lo stop), viene riaperta in automatico.

Protocollo: una riga JSON per richiesta; la risposta finale è una riga con "ok".
  {"cmd":"ping"}                         -> {"ok":true}
  {"cmd":"verify","timeout":25}          -> {"ok":true|false,"error":...}
  {"cmd":"enroll","name":"Indice"}       -> righe {"event":...} poi {"ok":true,"handle":N}
  {"cmd":"remove","handle":N}            -> {"ok":true,"chip":bool}
  {"cmd":"rename","handle":N,"name":"…"} -> {"ok":true}
  {"cmd":"list"}                         -> {"ok":true,"templates":[...]}
  {"cmd":"release"}                      -> {"ok":true}   (chiude la sessione aperta)
  {"cmd":"reset"}                        -> {"ok":true}   (reset USB del lettore)

Socket: controlvault/arbiter.sock (0600, cartella dell'utente: altri utenti non
possono collegarsi né crearne uno finto; root/PAM si collega comunque).
Log: stderr (launchd lo scrive in controlvault/fparbiter.log).
"""
import sys, os, json, time, socket, threading, traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvfp_config as cfg
cfg.setup_path()

SOCK_PATH = cfg.SOCK_PATH
TPL = cfg.TEMPLATES
UNSTICK_CMDS = (0x0440006d, 0x04400068)          # discard enroll, capture-wait
UNSTICK_DATA = bytes.fromhex("000000000400000000000000")
BUSY = (0x85, 0x0f)                               # verify: chip ancora occupato


def log(m):
    sys.stderr.write(time.strftime("%H:%M:%S ") + m + "\n"); sys.stderr.flush()


def load_backend():
    """Moduli che parlano col lettore vero. I test lo sostituiscono con un finto."""
    import controlvault as C
    import secure
    return C, secure


# ----------------------------- template JSON -----------------------------
def load_templates():
    try:
        with open(TPL) as f:
            return json.load(f).get("templates", [])
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


# ----------------------------- lettore -----------------------------
class Reader:
    """Possiede il lettore. `lock` serializza le operazioni; la sessione di
    verifica (d, s) resta in cache finché non scade per inattività."""

    def __init__(self):
        self.lock = threading.Lock()
        self.d = None
        self.s = None
        self.last_used = 0.0

    # -- sessione --
    def begin(self):
        """Claim + reset + handshake (senza open: lo fa ogni operazione, perché
        enroll apre da sé). Su handshake impuntato (0B) tenta un reset USB."""
        C, secure = load_backend()
        try:
            d = C.ControlVault(); d.claim()
        except Exception as e:
            raise RuntimeError("claim fallito: %s" % e)
        try:
            s = secure.SecureSession(d); s.reset(); s.handshake()
            return C, d, s
        except Exception as e:
            log("handshake KO (%s) → reset USB e ritento" % e)
            try:
                d.dev.reset()
            except Exception as e2:
                log("reset USB non riuscito: %s" % e2)
            time.sleep(0.4)
            try:
                s = secure.SecureSession(d); s.reset(); s.handshake()
                return C, d, s
            except Exception as e3:
                try: d.release()
                except Exception: pass
                raise RuntimeError("handshake fallito anche dopo reset: %s" % e3)

    def close(self):
        """Chiude la sessione in cache e libera il lettore."""
        d, self.d, self.s = self.d, None, None
        if d is not None:
            try: d.release()
            except Exception: pass

    def verify_session(self, fresh=False):
        """Sessione aperta per la verifica. Ritorna (C, d, s, riusata)."""
        C, _ = load_backend()
        if (not fresh and self.s is not None
                and time.time() - self.last_used < cfg.SESSION_IDLE_TTL):
            return C, self.d, self.s, True
        self.close()
        C, d, s = self.begin()
        try:
            st, _ih = s.open()
        except Exception:
            try: d.release()
            except Exception: pass
            raise
        if st != 0:
            try: d.release()
            except Exception: pass
            raise RuntimeError("open 0x%x" % st)
        self.d, self.s = d, s
        self.last_used = time.time()
        return C, d, s, False

    def expire_if_idle(self):
        """Chiamata periodicamente: rilascia il lettore dopo l'inattività."""
        if self.s is None or not self.lock.acquire(False):
            return
        try:
            if self.s is not None and time.time() - self.last_used >= cfg.SESSION_IDLE_TTL:
                log("sessione inattiva → chiusa")
                self.close()
        finally:
            self.lock.release()


READER = Reader()


# ----------------------------- operazioni -----------------------------
def _arm_capture(C, d, s):
    stc = s.capture()[0]
    if stc != 0:
        for cw in UNSTICK_CMDS:
            try: d.transact(C.build_envelope(cw, UNSTICK_DATA, counter=2))
            except Exception: pass
        stc = s.capture()[0]
    return stc


def _verify_once(handles, timeout, fresh):
    """Un tentativo completo. Ritorna (risposta, riprova_con_sessione_nuova)."""
    C, d, s, reused = READER.verify_session(fresh=fresh)
    try:
        t0 = time.time(); misses = 0
        while time.time() - t0 < timeout:
            if _arm_capture(C, d, s) != 0:
                if reused:
                    return None, True        # sessione riusata scaduta lato chip
                time.sleep(0.2); continue
            remaining = max(1.0, timeout - (time.time() - t0))
            if not s.wait_finger(to=int(remaining * 1000)):
                break
            st2, res = 0, 0
            for _ in range(10):
                st2, res, _mid, _mh = s.verify(handles)
                if st2 not in BUSY:
                    break
                time.sleep(0.2)
            if res == 1:
                READER.last_used = time.time()
                log("verify ok ✓%s" % (" (sessione riusata)" if reused else ""))
                return {"ok": True}, False
            if res != 0 and reused:
                return None, True            # risposta anomala su sessione riusata
            misses += 1
            if misses >= cfg.VERIFY_MAX_MISSES:
                READER.last_used = time.time()
                log("verify: troppi tocchi non combacianti")
                return {"ok": False, "error": "non riconosciuta"}, False
            time.sleep(0.3)
        READER.last_used = time.time()
        return {"ok": False, "error": "timeout"}, False
    except Exception:
        READER.close()
        if reused:
            return None, True                # es. lettore ricollegato dopo lo stop
        raise


def op_verify(timeout=25.0):
    """Cattura + match. Riprova entro la finestra sui tocchi non combacianti."""
    handles = _handles()
    if not handles:
        return {"ok": False, "error": "nessun template registrato"}
    with READER.lock:
        try:
            resp, retry = _verify_once(handles, timeout, fresh=False)
            if retry:
                log("sessione riusata non più valida → riapro")
                READER.close()
                resp, _ = _verify_once(handles, timeout, fresh=True)
            return resp or {"ok": False, "error": "lettore non pronto"}
        except Exception as e:
            log("verify errore: %s" % e)
            READER.close()
            return {"ok": False, "error": str(e)}


def op_enroll(name=None, on_event=None):
    def ev(m):
        if on_event:
            try: on_event(m)
            except Exception: pass
    with READER.lock:
        READER.close()                       # enroll usa una sessione tutta sua
        d = None
        try:
            _C, d, s = READER.begin()
            ok, last, stages, _cst, handle, tid = s.enroll(
                target_stages=cfg.ENROLL_STAGES, max_stages=cfg.ENROLL_MAX_STAGES,
                on_event=ev)
            if not ok or handle == 0:
                return {"ok": False,
                        "error": "enroll fallito (status=0x%x stadi=%d)" % (last, stages)}
            rec = {"handle": handle, "id": tid.hex(), "stages": stages,
                   "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
            if name:
                rec["name"] = name
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
    chip_ok = False
    with READER.lock:
        READER.close()
        d = None
        try:
            if handle:
                _C, d, s = READER.begin()
                st, _ih = s.open72()
                if st == 0:
                    st2, _ = s.delete_object(handle)
                    chip_ok = (st2 == 0)
        except Exception as e:
            log("remove errore: %s" % e)
        finally:
            try:
                if d: d.release()
            except Exception:
                pass
        # scollega comunque dal JSON: non deve più valere per sudo/sblocco
        save_templates([x for x in load_templates() if x.get("handle") != handle])
    return {"ok": True, "chip": bool(chip_ok)}


def op_rename(handle, name):
    with READER.lock:
        items = load_templates()
        found = False
        for it in items:
            if it.get("handle") == handle:
                it["name"] = name; found = True
        if found:
            save_templates(items)
    return {"ok": found} if found else {"ok": False, "error": "handle sconosciuto"}


def op_release():
    with READER.lock:
        READER.close()
    return {"ok": True}


def op_reset():
    with READER.lock:
        READER.close()
        try:
            C, _ = load_backend()
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
        # ha "ok". Così CLI e GUI mostrano "appoggia il dito" in tempo reale.
        return op_enroll(name=obj.get("name"),
                         on_event=(lambda m: send({"event": m})) if send else None)
    if cmd == "remove":
        return op_remove(obj.get("handle"))
    if cmd == "rename":
        return op_rename(obj.get("handle"), obj.get("name") or "")
    if cmd == "list":
        return {"ok": True, "templates": load_templates()}
    if cmd == "release":
        return op_release()
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

        def send(o):
            conn.sendall((json.dumps(o) + "\n").encode())

        try:
            obj = json.loads(line.decode("utf-8"))
        except Exception as e:
            send({"ok": False, "error": "json: %s" % e})
            return
        resp = handle_request(obj, send)   # può inviare eventi di streaming
        send(resp)                         # riga finale (contiene "ok")
    except Exception:
        log("conn errore:\n" + traceback.format_exc())
    finally:
        try: conn.close()
        except Exception: pass


def make_server(path=None):
    path = path or SOCK_PATH
    if os.path.exists(path):
        try: os.unlink(path)
        except Exception: pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)                  # nasce già 0600, senza finestre aperte
    try:
        srv.bind(path)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    srv.listen(8)
    return srv


def serve_forever(srv):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return                          # socket chiuso
        threading.Thread(target=serve_conn, args=(conn,), daemon=True).start()


def _reaper():
    while True:
        time.sleep(5.0)
        try:
            READER.expire_if_idle()
        except Exception:
            pass


def main():
    srv = make_server()
    threading.Thread(target=_reaper, daemon=True).start()
    log("FP Arbiter in ascolto su %s" % SOCK_PATH)
    serve_forever(srv)


if __name__ == "__main__":
    main()
