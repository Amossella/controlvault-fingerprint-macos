"""Funzioni pure del protocollo (nessun lettore) e coerenza della configurazione."""
import os, struct, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import cvfp_config as cfg
cfg.setup_path()

try:
    import controlvault as C      # richiede pyusb
    import secure                 # richiede pycryptodome
except Exception:                 # pragma: no cover
    C = secure = None


class ConfigTests(unittest.TestCase):
    def test_percorsi_relativi_al_progetto(self):
        self.assertEqual(cfg.ROOT, ROOT)
        self.assertTrue(cfg.TEMPLATES.startswith(ROOT))
        self.assertTrue(cfg.SOCK_PATH.startswith(ROOT))

    def test_socket_entro_il_limite_dei_socket_unix(self):
        self.assertLess(len(cfg.SOCK_PATH.encode()), 104)

    def test_nessun_percorso_utente_cablato_nel_codice(self):
        offenders = []
        for folder in ("tools", "tests", "controlvault"):
            for name in os.listdir(os.path.join(ROOT, folder)):
                if name.endswith((".py", ".sh", ".c", ".plist")):
                    with open(os.path.join(ROOT, folder, name), encoding="utf-8") as f:
                        if "/Users/" in f.read().replace('"/Users/"', ""):
                            offenders.append(name)
        self.assertEqual(offenders, [])


@unittest.skipIf(C is None, "pyusb/pycryptodome non disponibili")
class EnvelopeTests(unittest.TestCase):
    def test_envelope_andata_e_ritorno(self):
        pkt = C.build_envelope(0x00410023, b"\x01\x02\x03\x04", counter=2, handle=0x55)
        self.assertEqual(struct.unpack_from("<I", pkt, 4)[0], len(pkt))   # lunghezza totale
        r = C.parse_envelope(pkt)
        self.assertEqual((r["cmd"], r["counter"], r["handle"], r["data"]),
                         (0x00410023, 2, 0x55, b"\x01\x02\x03\x04"))

    def test_envelope_senza_dati(self):
        pkt = C.build_envelope(0x00400082)
        self.assertEqual(len(pkt), 44)
        self.assertEqual(C.parse_envelope(pkt)["data"], b"")

    def test_parse_commit_registrato(self):
        tid = bytes(range(20))
        pl = (b"\x03\x00\x00\x00" + b"\x00" * 8 + b"\x04\x00\x00\x00" +
              struct.pack("<I", 0xD01C30) + tid)
        self.assertEqual(secure.SecureSession.parse_commit(pl), (0xD01C30, tid))

    def test_parse_commit_blob_non_e_una_registrazione(self):
        self.assertEqual(secure.SecureSession.parse_commit(b"\xff" * 64), (0, b""))
        self.assertEqual(secure.SecureSession.parse_commit(b""), (0, b""))


if __name__ == "__main__":
    unittest.main()
