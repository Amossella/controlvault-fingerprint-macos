"""Flussi del demone di sblocco (fpunlock.Matcher) con arbitro e tastiera finti."""
import os, sys, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

try:
    import fpunlock as U          # richiede pyobjc (presente dove gira il demone)
except Exception as e:            # pragma: no cover
    U = None
    SKIP = "fpunlock non importabile: %s" % e


@unittest.skipIf(U is None, "pyobjc non disponibile")
class DaemonCase(unittest.TestCase):
    def setUp(self):
        self.m = U.Matcher()
        self.calls = []            # azioni "pericolose" eseguite, in ordine
        self.replies = []          # risposte dell'arbitro, in ordine
        self.field = True          # c'è un campo password a schermo?
        p = mock.patch.multiple(
            U,
            log=lambda m: None,
            get_password=lambda: "segreta",
            do_unlock=self._do_unlock,
            fill_auth=lambda pw: False,
            clear_field=lambda *a: self.calls.append("clear"),
            type_unicode=lambda s: self.calls.append("type:" + s),
            press_return=lambda: self.calls.append("return"),
            auth_present=lambda: self.field,
        )
        p.start(); self.addCleanup(p.stop)
        p = mock.patch.object(U.fpclient, "call", self._call)
        p.start(); self.addCleanup(p.stop)
        self.sleeps = []
        p = mock.patch.object(U.time, "sleep", self.sleeps.append)
        p.start(); self.addCleanup(p.stop)
        p = mock.patch.object(self.m, "_handles", lambda: [0x111])
        p.start(); self.addCleanup(p.stop)

    def _call(self, obj, wait=0):
        self.assertEqual(obj["cmd"], "verify")
        if not self.replies:
            # copione finito: fai uscire il demone dai suoi cicli
            self.m.locked.clear(); self.m.auth.clear()
            return {"ok": False, "error": "timeout"}
        r = self.replies.pop(0)
        return r(self) if callable(r) else r

    def _do_unlock(self, pw):
        self.calls.append("unlock:" + pw)
        self.m.locked.clear()      # lo schermo si sblocca


class LockTests(DaemonCase):
    def test_match_sblocca_con_la_password(self):
        self.replies = [{"ok": True}]
        self.m.locked.set(); self.m.handle_lock()
        self.assertEqual(self.calls, ["unlock:segreta"])

    def test_dito_non_riconosciuto_riprova(self):
        self.replies = [{"ok": False, "error": "non riconosciuta"},
                        {"ok": False, "error": "timeout"}, {"ok": True}]
        self.m.locked.set(); self.m.handle_lock()
        self.assertEqual(self.calls, ["unlock:segreta"])
        self.assertEqual(self.sleeps, [])              # nessuna pausa: ritenta subito

    def test_errore_del_lettore_fa_una_pausa(self):
        self.replies = [{"ok": False, "error": "handshake fallito"}, {"ok": True}]
        self.m.locked.set(); self.m.handle_lock()
        self.assertIn(1.0, self.sleeps)                # niente ciclo a vuoto sul chip
        self.assertEqual(self.calls, ["unlock:segreta"])

    def test_arbitro_assente_aspetta_senza_sbloccare(self):
        self.replies = [{"ok": False, "error": "no-arbiter"}]
        self.m.locked.set(); self.m.handle_lock()
        self.assertEqual(self.calls, [])
        self.assertTrue(self.sleeps)

    def test_nessuna_impronta_registrata(self):
        with mock.patch.object(self.m, "_handles", lambda: []):
            self.m.locked.set(); self.m.handle_lock()
        self.assertFalse(self.m.locked.is_set())
        self.assertEqual(self.calls, [])


class AuthTests(DaemonCase):
    def run_auth(self):
        self.m.auth.set(); self.m.handle_auth()

    def test_match_svuota_il_campo_e_scrive_la_password(self):
        self.replies = [{"ok": True}]
        self.run_auth()
        self.assertEqual(self.calls, ["clear", "type:segreta", "return"])
        self.assertFalse(self.m.auth.is_set())         # evento chiuso + pausa di rispetto
        self.assertGreater(self.m.auth_cooldown, 0)

    def test_campo_sparito_durante_la_verifica_non_scrive(self):
        def vanish(case):
            case.field = False                         # il dialogo si chiude nel frattempo
            return {"ok": True}
        self.replies = [vanish]
        self.run_auth()
        self.assertEqual(self.calls, [])               # la password NON viene digitata

    def test_campo_gia_chiuso_non_chiede_nemmeno_il_dito(self):
        self.field = False
        self.replies = [{"ok": True}]
        self.run_auth()
        self.assertEqual(self.calls, [])
        self.assertEqual(len(self.replies), 1)         # nessuna verify inviata

    def test_dito_non_riconosciuto_non_scrive(self):
        self.replies = [{"ok": False, "error": "non riconosciuta"}]
        self.run_auth()
        self.assertEqual(self.calls, [])

    def test_arbitro_assente_non_scrive(self):
        self.replies = [{"ok": False, "error": "no-arbiter"}]
        self.run_auth()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.m.auth.is_set())

    def test_accessibilita_riuscita_non_usa_la_tastiera(self):
        self.replies = [{"ok": True}]
        with mock.patch.object(U, "fill_auth", lambda pw: True):
            self.run_auth()
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
