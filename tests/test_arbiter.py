"""Logica dell'arbitro con il finto lettore (nessun hardware)."""
import json, os, shutil, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

import fparbiterd as A
import cvfp_config as cfg
from fakes import World


class ArbiterCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp", prefix="cvfp")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.world = World()
        self._saved = (A.load_backend, A.TPL, A.READER, A.time.sleep, A.log,
                       cfg.SESSION_IDLE_TTL)
        A.load_backend = self.world.backend
        A.TPL = os.path.join(self.tmp, "mac_template.json")
        A.READER = A.Reader()
        A.time.sleep = lambda s: None          # niente attese reali
        A.log = lambda m: None
        self.addCleanup(self._restore)
        self.set_templates([{"handle": 0x111, "name": "Indice"}])

    def _restore(self):
        A.READER.close()
        (A.load_backend, A.TPL, A.READER, A.time.sleep, A.log,
         cfg.SESSION_IDLE_TTL) = self._saved

    def set_templates(self, items):
        with open(A.TPL, "w") as f:
            json.dump({"templates": items}, f)

    def templates(self):
        with open(A.TPL) as f:
            return json.load(f)["templates"]


class VerifyTests(ArbiterCase):
    def test_match_al_primo_tocco(self):
        self.world.fingers = [True]; self.world.results = [1]
        self.assertEqual(A.op_verify(5), {"ok": True})

    def test_tocco_mancato_poi_match(self):
        self.world.fingers = [True, True]; self.world.results = [0, 1]
        self.assertEqual(A.op_verify(5), {"ok": True})

    def test_troppi_tocchi_non_riconosciuti(self):
        n = cfg.VERIFY_MAX_MISSES
        self.world.fingers = [True] * (n + 3); self.world.results = [0] * (n + 3)
        r = A.op_verify(5)
        self.assertEqual(r, {"ok": False, "error": "non riconosciuta"})
        self.assertEqual(len(self.world.fingers), 3)      # si è fermato a n tocchi

    def test_nessun_dito_timeout(self):
        self.assertEqual(A.op_verify(5), {"ok": False, "error": "timeout"})

    def test_nessun_template(self):
        self.set_templates([])
        r = A.op_verify(5)
        self.assertFalse(r["ok"])
        self.assertEqual(self.world.handshakes, 0)        # non tocca il lettore

    def test_chip_occupato_poi_risultato(self):
        self.world.fingers = [True]; self.world.results = [1]
        self.world.busy_before_result = 3
        self.assertEqual(A.op_verify(5), {"ok": True})

    def test_capture_impuntata_si_sblocca(self):
        self.world.capture_statuses = [0x85]              # la prima fallisce, la seconda no
        self.world.fingers = [True]; self.world.results = [1]
        self.assertEqual(A.op_verify(5), {"ok": True})

    def test_open_fallita_libera_il_lettore(self):
        self.world.open_status = 0x0f
        r = A.op_verify(5)
        self.assertFalse(r["ok"]); self.assertIn("open 0xf", r["error"])
        self.assertEqual(self.world.claimed(), [])


class SessionReuseTests(ArbiterCase):
    def test_seconda_verifica_riusa_la_sessione(self):
        self.world.fingers = [True, True]; self.world.results = [1, 1]
        self.assertTrue(A.op_verify(5)["ok"])
        self.assertTrue(A.op_verify(5)["ok"])
        self.assertEqual(self.world.handshakes, 1)
        self.assertEqual(len(self.world.claimed()), 1)    # lettore tenuto, una volta sola

    def test_sessione_riusata_anche_dopo_un_timeout(self):
        A.op_verify(5)                                    # nessun dito
        self.world.fingers = [True]; self.world.results = [1]
        self.assertTrue(A.op_verify(5)["ok"])
        self.assertEqual(self.world.handshakes, 1)

    def test_sessione_scaduta_per_inattivita(self):
        self.world.fingers = [True, True]; self.world.results = [1, 1]
        A.op_verify(5)
        A.READER.last_used = time.time() - cfg.SESSION_IDLE_TTL - 1
        A.op_verify(5)
        self.assertEqual(self.world.handshakes, 2)
        self.assertEqual(len(self.world.claimed()), 1)    # la vecchia è stata rilasciata

    def test_reaper_chiude_la_sessione_inattiva(self):
        self.world.fingers = [True]; self.world.results = [1]
        A.op_verify(5)
        A.READER.expire_if_idle()
        self.assertEqual(len(self.world.claimed()), 1)    # non ancora scaduta
        A.READER.last_used = time.time() - cfg.SESSION_IDLE_TTL - 1
        A.READER.expire_if_idle()
        self.assertEqual(self.world.claimed(), [])

    def test_sessione_dimenticata_dal_chip_viene_riaperta(self):
        self.world.fingers = [True, True]; self.world.results = [1, 1]
        A.op_verify(5)
        self.world.invalidate_sessions()                  # es. dopo lo stop del Mac
        self.assertEqual(A.op_verify(5), {"ok": True})
        self.assertEqual(self.world.handshakes, 2)
        self.assertEqual(len(self.world.claimed()), 1)

    def test_risposta_anomala_su_sessione_riusata_riapre(self):
        self.world.fingers = [True, True, True]; self.world.results = [1, -1, 1]
        A.op_verify(5)
        self.assertEqual(A.op_verify(5), {"ok": True})
        self.assertEqual(self.world.handshakes, 2)

    def test_release_chiude_la_sessione(self):
        self.world.fingers = [True]; self.world.results = [1]
        A.op_verify(5)
        self.assertEqual(A.op_release(), {"ok": True})
        self.assertEqual(self.world.claimed(), [])


class HandshakeTests(ArbiterCase):
    def test_handshake_0B_reset_usb_e_riprova(self):
        self.world.handshake_failures = 1
        self.world.fingers = [True]; self.world.results = [1]
        self.assertEqual(A.op_verify(5), {"ok": True})
        self.assertEqual(self.world.usb_resets, 1)

    def test_handshake_fallita_due_volte_libera_il_lettore(self):
        self.world.handshake_failures = 2
        r = A.op_verify(5)
        self.assertFalse(r["ok"]); self.assertIn("handshake", r["error"])
        self.assertEqual(self.world.claimed(), [])


class EnrollTests(ArbiterCase):
    def test_enroll_salva_e_manda_gli_eventi(self):
        events = []
        r = A.op_enroll(name="Pollice", on_event=events.append)
        self.assertEqual(r, {"ok": True, "handle": 0xABC123, "count": 2})
        self.assertEqual(events, self.world.enroll_events)
        rec = self.templates()[-1]
        self.assertEqual((rec["handle"], rec["name"], rec["stages"]), (0xABC123, "Pollice", 8))
        self.assertEqual(self.world.claimed(), [])

    def test_enroll_non_apre_la_sessione_prima(self):
        # regressione: una open prima di enroll dava 0xf con 0 stadi
        self.assertTrue(A.op_enroll()["ok"])
        self.assertFalse(any(s.opened for s in self.world.sessions))

    def test_enroll_dopo_verify_non_riusa_la_sessione_aperta(self):
        self.world.fingers = [True]; self.world.results = [1]
        A.op_verify(5)
        self.assertTrue(A.op_enroll()["ok"])
        self.assertEqual(self.world.claimed(), [])

    def test_enroll_stesso_handle_non_duplica(self):
        A.op_enroll(); A.op_enroll()
        self.assertEqual([t["handle"] for t in self.templates()], [0x111, 0xABC123])

    def test_enroll_fallito_non_tocca_il_file(self):
        self.world.enroll_result = (False, 0x8d, 2, None, 0, b"")
        r = A.op_enroll()
        self.assertFalse(r["ok"])
        self.assertEqual(len(self.templates()), 1)
        self.assertEqual(self.world.claimed(), [])

    def test_salvataggio_atomico_non_lascia_file_temporanei(self):
        A.op_enroll()
        self.assertEqual(os.listdir(self.tmp), ["mac_template.json"])


class RemoveRenameTests(ArbiterCase):
    def test_remove_cancella_dal_chip_e_dal_file(self):
        self.assertEqual(A.op_remove(0x111), {"ok": True, "chip": True})
        self.assertEqual(self.world.deleted, [0x111])
        self.assertEqual(self.templates(), [])
        self.assertEqual(self.world.claimed(), [])

    def test_remove_rifiutata_dal_chip_scollega_comunque(self):
        self.world.delete_status = 0x33
        self.assertEqual(A.op_remove(0x111), {"ok": True, "chip": False})
        self.assertEqual(self.templates(), [])

    def test_rename(self):
        self.assertEqual(A.op_rename(0x111, "Medio"), {"ok": True})
        self.assertEqual(self.templates()[0]["name"], "Medio")
        self.assertFalse(A.op_rename(0x999, "x")["ok"])

    def test_reset_usb(self):
        self.assertEqual(A.op_reset(), {"ok": True})
        self.assertEqual(self.world.usb_resets, 1)
        self.assertEqual(self.world.claimed(), [])

    def test_comando_sconosciuto(self):
        self.assertFalse(A.handle_request({"cmd": "boh"})["ok"])


if __name__ == "__main__":
    unittest.main()
