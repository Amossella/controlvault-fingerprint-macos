#!/usr/local/bin/python3
"""Demone impronta (user-space, non PAM).

Due funzioni:
  1) SBLOCCO SCHERMO: rileva il lock; al MATCH inserisce la password (Keychain)
     nel campo di sblocco via ACCESSIBILITY e invia Invio.
  2) DIALOGHI PASSWORD (Impostazioni di Sistema, sudo in Terminale, ecc.): rileva un
     campo password col focus tramite SECURE INPUT (IsSecureEventInputEnabled). Al MATCH
     scrive la password + Invio via CGEvent, che buca il Secure Input anche sui dialoghi
     LocalAuthentication delle Impostazioni (invisibili ad Accessibility). Sui vecchi
     dialoghi SecurityAgent usa prima Accessibility, poi CGEvent come fallback.

La password viene scritta SOLO (a) dopo un'impronta riconosciuta e (b) quando il
Secure Input e' attivo, cioe' solo quando un vero campo password ha il focus — mai
"sparsa" in campi di testo normali.

Setup:
  1) Password nel Keychain:
        security add-generic-password -U -a "$USER" -s cv-fp-unlock -w
  2) Permesso ACCESSIBILITA' per questo processo (lo chiede al primo avvio).

Il lettore NON viene aperto qui: il match lo esegue l'arbitro (fparbiterd), che
deve essere attivo. Questo processo si limita a scrivere la password.

Test:  python3 tools/fpunlock.py   (Ctrl+C per uscire)
"""
import sys, os, time, threading, subprocess, ctypes, ctypes.util

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvfp_config as cfg
import fpclient   # il lettore lo apre SOLO l'arbitro (fparbiterd): qui si chiede a lui

import objc
from Foundation import NSObject, NSDistributedNotificationCenter, NSRunLoop, NSDate
from AppKit import NSWorkspace
from Quartz import CGEventCreateKeyboardEvent, CGEventKeyboardSetUnicodeString, CGEventPost, kCGHIDEventTap
from ApplicationServices import (
    AXIsProcessTrustedWithOptions, AXUIElementCreateSystemWide, AXUIElementCreateApplication,
    AXUIElementCopyAttributeValue, AXUIElementSetAttributeValue,
    kAXFocusedUIElementAttribute, kAXValueAttribute, kAXRoleAttribute,
    kAXWindowsAttribute, kAXChildrenAttribute)

KC_SERVICE = cfg.KC_SERVICE
RETURN_KEYCODE = 36

# Carbon: Secure Input attivo => c'e' un campo password col focus (dialoghi
# LocalAuthentication delle Impostazioni, prompt password in Terminale, ecc.).
# Questi dialoghi sono INVISIBILI ad Accessibility, ma i CGEvent li bucano
# (verificato sul device): quindi al match scriviamo la password via CGEvent.
try:
    _carbon = ctypes.CDLL(ctypes.util.find_library("Carbon") or
                          "/System/Library/Frameworks/Carbon.framework/Carbon")
except Exception:
    _carbon = None


def secure_input_active():
    """True se un campo sicuro ha il focus da qualche parte (Secure Event Input)."""
    if _carbon is None:
        return False
    try:
        return bool(_carbon.IsSecureEventInputEnabled())
    except Exception:
        return False
# nomi/bundle dei processi che mostrano il campo password (lock screen e dialoghi admin)
SECAGENT_KEYS = ("SecurityAgent", "loginwindow", "ScreenSaver", "authorizationhost",
                 "CoreAuthenticationAgent")


def log(m):
    sys.stderr.write(time.strftime("%H:%M:%S ") + m + "\n"); sys.stderr.flush()


def ax_trusted(prompt=True):
    try:
        return bool(AXIsProcessTrustedWithOptions({"AXTrustedCheckOptionPrompt": bool(prompt)}))
    except Exception:
        return False


def get_password():
    try:
        out = subprocess.run(["security", "find-generic-password", "-s", KC_SERVICE, "-w"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            return out.stdout.rstrip("\n")
    except Exception as e:
        log("keychain errore: %s" % e)
    return None


def _attr(el, attr):
    err, val = AXUIElementCopyAttributeValue(el, attr, None)
    return val if err == 0 else None


def _role(el):
    r = _attr(el, kAXRoleAttribute)
    return str(r) if r else "?"


def find_text_fields(el, depth=0, out=None, maxdepth=14):
    """Tutti i campi di testo (inclusi i sicuri) — usato dallo sblocco schermo."""
    if out is None:
        out = []
    if el is None or depth > maxdepth:
        return out
    role = _role(el)
    if "TextField" in role or "SecureTextField" in role:
        out.append(el)
    for ch in (_attr(el, kAXChildrenAttribute) or []):
        find_text_fields(ch, depth + 1, out, maxdepth)
    return out


def find_fields(el, depth=0, secure=None, plain=None, maxdepth=14):
    """Separa campi sicuri (password) da campi normali (es. username)."""
    if secure is None:
        secure, plain = [], []
    if el is None or depth > maxdepth:
        return secure, plain
    role = _role(el)
    if "SecureTextField" in role:
        secure.append(el)
    elif "TextField" in role:
        plain.append(el)
    for ch in (_attr(el, kAXChildrenAttribute) or []):
        find_fields(ch, depth + 1, secure, plain, maxdepth)
    return secure, plain


def _secagent_apps():
    out = []
    try:
        for app in NSWorkspace.sharedWorkspace().runningApplications():
            name = (app.localizedName() or "")
            bid = (app.bundleIdentifier() or "")
            if any(k in (name + " " + bid) for k in SECAGENT_KEYS):
                out.append((name or bid, app.processIdentifier()))
    except Exception as e:
        log("enum app errore: %s" % e)
    return out


def auth_dialog_pid():
    """pid di un SecurityAgent con un campo password visibile, altrimenti None."""
    for name, pid in _secagent_apps():
        try:
            axapp = AXUIElementCreateApplication(pid)
            for w in (_attr(axapp, kAXWindowsAttribute) or []):
                sec, _ = find_fields(w)
                if sec:
                    return pid
        except Exception:
            pass
    return None


def auth_present():
    """C'e' un campo password che aspetta input? (Secure Input, o dialogo AX legacy)."""
    if secure_input_active():
        return True
    return auth_dialog_pid() is not None


def press_return():
    for down in (True, False):
        CGEventPost(kCGHIDEventTap, CGEventCreateKeyboardEvent(None, RETURN_KEYCODE, down))


def type_unicode(s):
    for ch in s:
        for down in (True, False):
            e = CGEventCreateKeyboardEvent(None, 0, down)
            CGEventKeyboardSetUnicodeString(e, len(ch), ch)
            CGEventPost(kCGHIDEventTap, e)
        time.sleep(0.01)


def clear_field(n=48):
    """Svuota il campo con molti Backspace PRIMA di scrivere. Senza questo, a
    ogni tentativo fallito la password si SOMMA alla precedente → 'molto più
    lunga' → rifiutata. Backspace è affidabile anche nei campi sicuri (a
    differenza di Cmd+A)."""
    for _ in range(n):
        for down in (True, False):
            CGEventPost(kCGHIDEventTap, CGEventCreateKeyboardEvent(None, 51, down))
    time.sleep(0.05)


def do_unlock(pw):
    """SBLOCCO SCHERMO: riempie i campi del lock screen e invia Invio."""
    fields = []
    for name, pid in _secagent_apps():
        try:
            axapp = AXUIElementCreateApplication(pid)
            wins = _attr(axapp, kAXWindowsAttribute) or []
            log("  AX app '%s' finestre=%d" % (name, len(wins)))
            for w in wins:
                fields += find_text_fields(w)
        except Exception as e:
            log("  AX enum errore: %s" % e)
    try:
        foc = _attr(AXUIElementCreateSystemWide(), kAXFocusedUIElementAttribute)
        if foc is not None and "TextField" in _role(foc):
            fields.insert(0, foc)
    except Exception as e:
        log("  AX focus errore: %s" % e)

    log("  campi trovati: %d" % len(fields))
    done = False
    for f in fields:
        try:
            if AXUIElementSetAttributeValue(f, kAXValueAttribute, pw) == 0:
                done = True
        except Exception:
            pass
    if not done:
        log("  AX non ha riempito nulla -> CGEvent typing")
        type_unicode(pw)
    time.sleep(0.15)
    press_return()


def fill_auth(pw):
    """DIALOGO AUTORIZZAZIONE: imposta password nei campi sicuri di SecurityAgent."""
    user = os.environ.get("USER") or ""
    filled = False
    for name, pid in _secagent_apps():
        try:
            axapp = AXUIElementCreateApplication(pid)
            for w in (_attr(axapp, kAXWindowsAttribute) or []):
                sec, plain = find_fields(w)
                for f in plain:   # eventuale campo "nome utente" vuoto
                    cur = _attr(f, kAXValueAttribute)
                    if (cur is None or str(cur) == "") and user:
                        try: AXUIElementSetAttributeValue(f, kAXValueAttribute, user)
                        except Exception: pass
                for f in sec:
                    try:
                        err = AXUIElementSetAttributeValue(f, kAXValueAttribute, pw)
                        log("  setAXValue password -> err=%s" % err)
                        if err == 0:
                            filled = True
                    except Exception as e:
                        log("  setAXValue errore: %s" % e)
        except Exception as e:
            log("  fill_auth errore: %s" % e)
    if filled:
        time.sleep(0.15)
        press_return()
    else:
        log("  AX non ha potuto scrivere nel campo di SecurityAgent (Secure Input/permessi)")
    return filled


class Matcher(threading.Thread):
    """Reagisce a schermo bloccato / pop-up password: chiede il match all'arbitro
    e, se l'impronta è riconosciuta, scrive la password."""

    def __init__(self):
        super().__init__(daemon=True)
        self.locked = threading.Event()   # schermo bloccato
        self.auth = threading.Event()     # campo password presente
        self.stop = threading.Event()
        self.auth_cooldown = 0.0
        self._arbiter_down = False        # per non ripetere l'avviso nel log

    def _handles(self):
        import json
        try:
            with open(cfg.TEMPLATES) as f:
                return [r["handle"] for r in json.load(f).get("templates", []) if r.get("handle")]
        except Exception:
            return []

    def _verify(self):
        """Un tentativo di match tramite l'arbitro.
        Ritorna True (riconosciuta), False (riprova) o None (arbitro assente)."""
        r = fpclient.call({"cmd": "verify", "timeout": cfg.UNLOCK_VERIFY_TIMEOUT},
                          wait=cfg.UNLOCK_VERIFY_TIMEOUT + 10.0)
        if r.get("ok"):
            self._arbiter_down = False
            return True
        err = r.get("error")
        if err == "no-arbiter":
            if not self._arbiter_down:
                log("arbitro (fparbiterd) non raggiungibile: impronta non disponibile")
                self._arbiter_down = True
            return None
        self._arbiter_down = False
        if err not in ("timeout", "non riconosciuta"):
            # errore del lettore (risposta immediata): pausa, o si martella il chip
            log("lettore: %s" % err)
            time.sleep(1.0)
        return False

    def _pause(self, seconds, flag):
        """Attesa interrompibile: finisce prima se `flag` si spegne o si esce."""
        t = 0.0
        while t < seconds and flag.is_set() and not self.stop.is_set():
            time.sleep(0.25); t += 0.25

    # ---- flusso sblocco schermo ----
    def handle_lock(self):
        if not self._handles():
            log("nessun template registrato"); self.locked.clear(); return
        log("schermo bloccato: appoggia il dito...")
        while self.locked.is_set() and not self.stop.is_set():
            ok = self._verify()
            if ok is None:
                self._pause(2.0, self.locked); continue
            if not ok:
                continue
            pw = get_password()
            if not pw:
                log("password non nel Keychain"); return
            log("impronta OK -> sblocco")
            do_unlock(pw)
            waited = 0.0
            while self.locked.is_set() and waited < 8.0:
                time.sleep(0.5); waited += 0.5
            if not self.locked.is_set():
                log("sbloccato ✓"); return
            log("ancora bloccato: ritento tra 3s"); self._pause(3.0, self.locked)

    # ---- flusso dialogo autorizzazione ----
    def handle_auth(self):
        try:
            pw = get_password()
            if not self._handles() or not pw:
                return
            log("campo password rilevato: appoggia il dito...")
            deadline = time.time() + cfg.AUTH_WINDOW
            while (self.auth.is_set() and not self.stop.is_set()
                   and not self.locked.is_set() and time.time() < deadline):
                if not auth_present():
                    log("campo password chiuso"); break
                ok = self._verify()
                if ok is None:
                    break
                if not ok:
                    continue
                # la verifica può durare secondi: se nel frattempo il campo password
                # è sparito, NON digitare (finirebbe nella finestra che ha il focus).
                if not auth_present():
                    log("campo password chiuso durante la verifica: non scrivo"); break
                log("impronta OK -> scrivo la password")
                # AX funziona solo sui dialoghi legacy; i dialoghi LocalAuthentication
                # (Impostazioni) sono invisibili ad AX, ma i CGEvent li raggiungono.
                if not fill_auth(pw):
                    clear_field()        # svuota residui di tentativi falliti
                    type_unicode(pw)
                    time.sleep(0.15)
                    press_return()
                waited = 0.0
                while auth_present() and waited < 6.0:
                    time.sleep(0.5); waited += 0.5
                log("autorizzato ✓" if not auth_present()
                    else "campo ancora presente (password errata?)")
                break
        finally:
            self.auth.clear(); self.auth_cooldown = time.time() + 3

    def run(self):
        while not self.stop.is_set():
            if self.locked.is_set():
                self.handle_lock()
            elif self.auth.is_set():
                self.handle_auth()
            else:
                time.sleep(0.2)


class AuthWatcher(threading.Thread):
    """Sorveglia la comparsa di un campo password (Secure Input o dialogo AX legacy),
    fuori dal lock schermo."""
    def __init__(self, matcher):
        super().__init__(daemon=True)
        self.m = matcher

    def run(self):
        while not self.m.stop.is_set():
            time.sleep(0.6)
            if self.m.locked.is_set() or self.m.auth.is_set():
                continue
            if time.time() < self.m.auth_cooldown:
                continue
            if auth_present():
                log("rilevato campo password (richiesta autorizzazione)")
                self.m.auth.set()


class Observer(NSObject):
    def initWithMatcher_(self, matcher):
        self = objc.super(Observer, self).init()
        if self is None:
            return None
        self.matcher = matcher
        return self

    def locked_(self, note):
        log("== schermo BLOCCATO ==")
        self.matcher.locked.set()

    def unlocked_(self, note):
        log("== schermo SBLOCCATO ==")
        self.matcher.locked.clear()


def main():
    if not ax_trusted(prompt=True):
        log("PERMESSO ACCESSIBILITA' MANCANTE: abilita python3 in")
        log("Impostazioni -> Privacy e sicurezza -> Accessibilita', poi riavvia.")
    if not get_password():
        log('password non in Keychain: security add-generic-password -U -a "$USER" -s cv-fp-unlock -w')

    m = Matcher(); m.start()
    AuthWatcher(m).start()
    nc = NSDistributedNotificationCenter.defaultCenter()
    obs = Observer.alloc().initWithMatcher_(m)
    nc.addObserver_selector_name_object_(obs, "locked:", "com.apple.screenIsLocked", None)
    nc.addObserver_selector_name_object_(obs, "unlocked:", "com.apple.screenIsUnlocked", None)
    log("demone avviato: sblocco schermo + dialoghi autorizzazione. Appoggia il dito al bisogno.")
    try:
        rl = NSRunLoop.currentRunLoop()
        while True:
            rl.runMode_beforeDate_("kCFRunLoopDefaultMode", NSDate.dateWithTimeIntervalSinceNow_(1.0))
    except KeyboardInterrupt:
        log("uscita."); m.stop.set()


if __name__ == "__main__":
    main()
