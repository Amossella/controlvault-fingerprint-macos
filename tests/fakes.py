"""Finto lettore ControlVault per i test: sostituisce i moduli `controlvault` e
`secure` usati dall'arbitro, così tutta la catena (arbitro → socket → client →
demone/sudo) si prova senza hardware e senza dito.

Uso tipico:
    world = World()
    fparbiterd.load_backend = world.backend
    world.fingers = [True]; world.results = [1]     # un tocco, riconosciuto
"""
import types


class World:
    """Stato del finto lettore + copione di ciò che deve succedere."""

    def __init__(self):
        self.devices = []            # FakeControlVault creati
        self.sessions = []           # FakeSecureSession create
        self.handshakes = 0
        self.handshake_failures = 0  # quante handshake devono fallire (0B)
        self.usb_resets = 0
        self.open_status = 0
        self.capture_statuses = []   # coda di status per capture (default 0)
        self.fingers = []            # coda di esiti wait_finger (default False)
        self.results = []            # coda di esiti verify: 1 match, 0 no, -1 anomalo
        self.busy_before_result = 0  # quante verify rispondono "occupato" prima
        self.generation = 0          # ++ quando il chip "dimentica" le sessioni
        self.enroll_events = ["[tocco 1]", "   >> APPOGGIA E SOLLEVA IL DITO", "   STAGE OK #1"]
        self.enroll_result = (True, 0, 8, 0, 0xABC123, bytes.fromhex("aa" * 20))
        self.deleted = []
        self.delete_status = 0

    # -- copione --
    def invalidate_sessions(self):
        """Simula il chip che scarta le sessioni aperte (stop, timeout interno)."""
        self.generation += 1

    def claimed(self):
        return [d for d in self.devices if d.is_claimed]

    def backend(self):
        w = self
        C = types.SimpleNamespace(
            ControlVault=lambda: FakeControlVault(w),
            build_envelope=lambda *a, **k: b"")
        secure = types.SimpleNamespace(SecureSession=lambda d: FakeSecureSession(w, d))
        return C, secure


class FakeUSB:
    def __init__(self, world):
        self.w = world

    def reset(self):
        self.w.usb_resets += 1


class FakeControlVault:
    def __init__(self, world):
        self.w = world
        self.dev = FakeUSB(world)
        self.is_claimed = False
        world.devices.append(self)

    def claim(self, wait=4.0):
        if self.w.claimed():
            raise RuntimeError("lettore occupato da un altro processo")
        self.is_claimed = True

    def release(self):
        self.is_claimed = False

    def transact(self, pkt, timeout=5000):
        return {"status": 0, "data": b"", "handle": 0}


class FakeSecureSession:
    def __init__(self, world, dev):
        self.w = world
        self.d = dev
        self.generation = world.generation
        self.opened = False
        self.ihandle = 0
        world.sessions.append(self)

    def _stale(self):
        return self.generation != self.w.generation

    def reset(self):
        pass

    def handshake(self, reinit=True, retries=3):
        self.w.handshakes += 1
        if self.w.handshake_failures > 0:
            self.w.handshake_failures -= 1
            raise RuntimeError("handshake fallito dopo 3 tentativi (lettore non pronto): "
                               "chiave pubblica non valida (risposta 0B)")
        self.generation = self.w.generation
        return True

    def open(self):
        if self.opened:
            raise AssertionError("doppia open sulla stessa sessione")
        self.opened = self.w.open_status == 0
        self.ihandle = 0x1234
        return self.w.open_status, self.ihandle

    def open72(self, appid=None, userid=None):
        self.opened = True
        return 0, 0x1234

    def capture(self, to=6000):
        if self._stale():
            return 0x0f, b"", b"", b""
        st = self.w.capture_statuses.pop(0) if self.w.capture_statuses else 0
        return st, b"R" * 20, b"", b""

    def wait_finger(self, to=20000):
        return self.w.fingers.pop(0) if self.w.fingers else False

    def verify(self, handles, to=6000):
        if self.w.busy_before_result > 0:
            self.w.busy_before_result -= 1
            return 0x85, 0, b"", 0
        res = self.w.results.pop(0) if self.w.results else 0
        return 0, res, b"", (handles[0] if res == 1 else 0)

    def enroll(self, target_stages=4, max_stages=12, on_event=None):
        # l'enroll apre la sessione da sé: se è già aperta il chip risponde 0xf
        if self.opened:
            return False, 0x0f, 0, None, 0, b""
        for m in self.w.enroll_events:
            if on_event:
                on_event(m)
        return self.w.enroll_result

    def delete_object(self, handle, to=6000):
        self.w.deleted.append(handle)
        return self.w.delete_status, b""
