"""Configurazione unica del progetto: percorsi, tempi e soglie.

Tutti i percorsi derivano dalla posizione di questo file, quindi il progetto
funziona da qualunque cartella venga clonato (nessun percorso personale cablato).
"""
import os, sys

TOOLS = os.path.dirname(os.path.abspath(__file__))     # .../tools
ROOT = os.path.dirname(TOOLS)                           # radice del progetto
CV = os.path.join(ROOT, "controlvault")                 # dati + driver USB

TEMPLATES = os.path.join(CV, "mac_template.json")       # impronte registrate
SOCK_PATH = os.path.join(CV, "arbiter.sock")            # socket dell'arbitro (0600)

KC_SERVICE = "cv-fp-unlock"       # voce del Keychain con la password di login

# --- registrazione ---
ENROLL_STAGES = 8                 # tocchi richiesti
ENROLL_MAX_STAGES = 14            # tocchi massimi prima di rinunciare

# --- verifica ---
VERIFY_MAX_MISSES = 5             # tocchi non riconosciuti prima di rinunciare
SUDO_TIMEOUT = 12.0               # secondi concessi a sudo per il dito
UNLOCK_VERIFY_TIMEOUT = 8.0       # durata di ogni tentativo a schermo bloccato
AUTH_WINDOW = 20.0                # quanto resta "in ascolto" un pop-up password
GUI_VERIFY_TIMEOUT = 15.0

# --- arbitro ---
SESSION_IDLE_TTL = 300.0          # la sessione col lettore resta aperta così a lungo


def setup_path():
    """Rende importabili i moduli del progetto (tools/ e controlvault/)."""
    for p in (CV, TOOLS):
        if p not in sys.path:
            sys.path.insert(0, p)
