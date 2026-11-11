"""Catena completa su socket vero: arbitro (finto lettore) ↔ fpclient ↔ fpauth."""
import io, json, os, shutil, stat, sys, tempfile, threading, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

import fparbiterd as A
import fpclient
import fpauth
from fakes import World


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp", prefix="cvfp")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.world = World()
        self.sock = os.path.join(self.tmp, "arbiter.sock")
        self._saved = (A.load_backend, A.TPL, A.READER, A.time.sleep, A.log,
                       fpclient.SOCK_PATH)
        A.load_backend = self.world.backend
        A.TPL = os.path.join(self.tmp, "mac_template.json")
        A.READER = A.Reader()
        A.time.sleep = lambda s: None
        A.log = lambda m: None
        fpclient.SOCK_PATH = self.sock
        self.addCleanup(self._restore)
        with open(A.TPL, "w") as f:
            json.dump({"templates": [{"handle": 0x111, "name": "Indice"}]}, f)
        self.srv = A.make_server(self.sock)
        threading.Thread(target=A.serve_forever, args=(self.srv,), daemon=True).start()
        self.addCleanup(self.srv.close)

    def _restore(self):
        A.READER.close()
        (A.load_backend, A.TPL, A.READER, A.time.sleep, A.log,
         fpclient.SOCK_PATH) = self._saved


class ClientServerTests(ServerCase):
    def test_socket_solo_per_il_proprietario(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.sock).st_mode), 0o600)

    def test_ping_e_list(self):
        self.assertTrue(fpclient.available())
        r = fpclient.call({"cmd": "list"})
        self.assertEqual(r["templates"][0]["handle"], 0x111)

    def test_verify(self):
        self.world.fingers = [True]; self.world.results = [1]
        self.assertTrue(fpclient.verify(5))
        self.assertFalse(fpclient.verify(1))               # nessun dito → timeout

    def test_enroll_in_streaming(self):
        events = []
        r = fpclient.call_stream({"cmd": "enroll", "name": "Pollice"}, on_event=events.append)
        self.assertTrue(r["ok"]); self.assertEqual(r["handle"], 0xABC123)
        self.assertEqual(events, self.world.enroll_events)

    def test_call_semplice_su_enroll_ritorna_la_riga_finale(self):
        r = fpclient.call({"cmd": "enroll"})
        self.assertIn("ok", r); self.assertNotIn("event", r)

    def test_richiesta_non_json(self):
        import socket
        c = socket.socket(socket.AF_UNIX); c.connect(self.sock)
        c.sendall(b"non-json\n")
        r = json.loads(c.makefile().readline()); c.close()
        self.assertFalse(r["ok"])

    def test_ping_risponde_mentre_una_verifica_aspetta_il_dito(self):
        gate = threading.Event()
        orig = self.world.backend
        def slow_backend():
            C, secure = orig()
            mk = secure.SecureSession
            def make(d):
                s = mk(d)
                s.wait_finger = lambda to=0: (gate.wait(5), False)[1]
                return s
            secure.SecureSession = make
            return C, secure
        A.load_backend = slow_backend
        t = threading.Thread(target=fpclient.verify, args=(5,)); t.start()
        try:
            self.assertTrue(fpclient.available())
        finally:
            gate.set(); t.join(10)


class ClientTrustTests(ServerCase):
    def test_arbitro_assente(self):
        self.srv.close(); os.unlink(self.sock)
        self.assertFalse(fpclient.available())
        self.assertEqual(fpclient.call({"cmd": "list"})["error"], "no-arbiter")

    def test_socket_di_un_altro_utente_rifiutato(self):
        real = os.stat
        def fake_stat(path, *a, **k):
            st = real(path, *a, **k)
            if path == self.sock:
                st = os.stat_result(st[:4] + (st.st_uid + 4242,) + st[5:])
            return st
        with mock.patch.object(fpclient.os, "stat", fake_stat):
            self.assertFalse(fpclient.available())
            self.assertEqual(fpclient.call({"cmd": "verify"})["error"], "no-arbiter")


class FpauthTests(ServerCase):
    def run_fpauth(self, *argv):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            rc = fpauth.main(list(argv))
        return rc, err.getvalue()

    def test_dito_riconosciuto_exit_0(self):
        self.world.fingers = [True]; self.world.results = [1]
        rc, msg = self.run_fpauth("--timeout", "3")
        self.assertEqual(rc, 0); self.assertIn("riconosciuta ✓", msg)

    def test_dito_sbagliato_exit_1(self):
        self.world.fingers = [True] * 9; self.world.results = [0] * 9
        rc, msg = self.run_fpauth("--timeout", "3")
        self.assertEqual(rc, 1); self.assertIn("uso la password", msg)

    def test_nessun_dito_exit_1(self):
        rc, msg = self.run_fpauth("--timeout", "1")
        self.assertEqual(rc, 1); self.assertIn("tempo scaduto", msg)

    def test_arbitro_assente_exit_1_senza_aprire_il_lettore(self):
        self.srv.close(); os.unlink(self.sock)
        rc, msg = self.run_fpauth("--timeout", "3")
        self.assertEqual(rc, 1); self.assertIn("non attivo", msg)
        self.assertEqual(self.world.handshakes, 0)


if __name__ == "__main__":
    unittest.main()
