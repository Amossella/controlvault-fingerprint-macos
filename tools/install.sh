#!/bin/bash
# =====================================================================
#  ControlVault Fingerprint for macOS — installer unico
#  Installa: dipendenze Python, modulo PAM per sudo, demone di sblocco
#  schermo (LaunchAgent) e l'app FP Manager.
#
#  Uso:   bash install.sh [opzioni]
#  Opzioni:
#     --no-pam      salta l'impronta per sudo
#     --no-unlock   salta il demone di sblocco schermo
#     --no-app      salta l'app FP Manager
#     --python PATH usa un python3 specifico (default: /usr/local/bin/python3)
# =====================================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"           # .../tools
ROOT="$(cd "$HERE/.." && pwd)"                   # .../usbcfg
PY="/usr/local/bin/python3"
DO_PAM=1; DO_UNLOCK=1; DO_APP=1

while [ $# -gt 0 ]; do
  case "$1" in
    --no-pam) DO_PAM=0;; --no-unlock) DO_UNLOCK=0;; --no-app) DO_APP=0;;
    --python) shift; PY="$1";;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "opzione sconosciuta: $1"; exit 1;;
  esac; shift
done

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "   \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "   \033[33m!\033[0m %s\n" "$*"; }

# ---------------------------------------------------------------------
say "1/6  Controllo Python"
if ! command -v "$PY" >/dev/null; then
  echo "python3 non trovato in: $PY"
  echo "Installa Python 3 (python.org) o indica il percorso con --python."
  exit 1
fi
PYBIN="$("$PY" -c 'import sys;print(sys.executable)')"
ok "Python: $PYBIN"

# ---------------------------------------------------------------------
say "2/6  Dipendenze Python (pip)"
DEPS="pyusb pycryptodome libusb_package"
[ "$DO_UNLOCK" = 1 ] && DEPS="$DEPS pyobjc-framework-Cocoa pyobjc-framework-Quartz pyobjc-framework-ApplicationServices"
if "$PY" -m pip install --user --upgrade $DEPS >/tmp/cvfp_pip.log 2>&1; then
  ok "installate: $DEPS"
else
  warn "pip con --user ha dato errore, riprovo senza..."
  "$PY" -m pip install --upgrade $DEPS >>/tmp/cvfp_pip.log 2>&1 \
    && ok "installate" || { echo "pip fallito, vedi /tmp/cvfp_pip.log"; exit 1; }
fi

# ---------------------------------------------------------------------
say "3/6  Rilevamento lettore (0a5c:5834)"
if "$PY" - <<PYEOF 2>/dev/null
import sys; sys.path.insert(0,"$ROOT/controlvault")
import usb.core, usb.backend.libusb1, libusb_package
be=usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
sys.exit(0 if usb.core.find(idVendor=0x0a5c,idProduct=0x5834,backend=be) else 1)
PYEOF
then ok "lettore rilevato"; else warn "lettore NON rilevato ora (puoi continuare lo stesso)"; fi

# ---------------------------------------------------------------------
if [ "$DO_PAM" = 1 ]; then
  say "4/6  Impronta per sudo (modulo PAM) — richiede la password admin"
  if ! command -v clang >/dev/null; then
    warn "clang assente (installa gli Xcode Command Line Tools: xcode-select --install) — salto il PAM"
  else
    clang -bundle -o "$HERE/pam_cvfp.so" "$HERE/pam_cvfp.c" -lpam 2>/tmp/cvfp_clang.log \
      && ok "pam_cvfp.so compilato" || { warn "compilazione PAM fallita (vedi /tmp/cvfp_clang.log) — salto"; DO_PAM=0; }
    if [ "$DO_PAM" = 1 ]; then
      sudo bash "$HERE/install_pam.sh" && ok "PAM installato per sudo" || warn "install_pam.sh fallito"
    fi
  fi
else
  say "4/6  Impronta per sudo — SALTATO (--no-pam)"
fi

# ---------------------------------------------------------------------
if [ "$DO_APP" = 1 ]; then
  say "5/6  App FP Manager"
  APP="/Applications/FP Manager.app"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  cat > "$APP/Contents/MacOS/fpmanager" <<EOF
#!/bin/bash
exec "$PY" "$HERE/fpmanager.py"
EOF
  chmod +x "$APP/Contents/MacOS/fpmanager"
  cp "$HERE/appbundle/Info.plist" "$APP/Contents/Info.plist" 2>/dev/null
  cp "$HERE/appbundle/app.icns"  "$APP/Contents/Resources/app.icns" 2>/dev/null
  /usr/bin/touch "$APP"
  ok "installata in $APP"
else
  say "5/6  App FP Manager — SALTATO (--no-app)"
fi

# ---------------------------------------------------------------------
if [ "$DO_UNLOCK" = 1 ]; then
  say "6/6  Sblocco schermo (demone)"
  # password login nel Keychain (serve a riempire il campo di sblocco)
  if ! security find-generic-password -s cv-fp-unlock -w >/dev/null 2>&1; then
    echo "   Per lo sblocco schermo serve la tua password di login nel Keychain."
    read -r -p "   Configurarla ora? [s/N] " ans
    if [ "${ans:-N}" = "s" ] || [ "${ans:-N}" = "S" ]; then
      security add-generic-password -U -a "$USER" -s cv-fp-unlock -w && ok "password salvata nel Keychain"
    else
      warn "saltata — lo sblocco schermo non funzionera' finche' non la imposti:"
      warn 'security add-generic-password -U -a "$USER" -s cv-fp-unlock -w'
    fi
  else
    ok "password gia' nel Keychain"
  fi
  bash "$HERE/install_unlock_agent.sh" >/dev/null 2>&1 && ok "demone installato e avviato" || warn "install_unlock_agent.sh fallito"
  echo
  warn "PERMESSO ACCESSIBILITA' (necessario per lo sblocco):"
  echo "     Impostazioni di Sistema -> Privacy e sicurezza -> Accessibilita' -> '+'"
  echo "     Cmd+Shift+G e incolla questo percorso, poi attiva l'interruttore:"
  printf "        \033[1m%s\033[0m\n" "$PYBIN"
  echo "     poi:  launchctl kickstart -k gui/\$(id -u)/com.cvfp.unlock"
else
  say "6/6  Sblocco schermo — SALTATO (--no-unlock)"
fi

# ---------------------------------------------------------------------
say "Fatto!"
echo "  • FP Manager: aprilo da Applicazioni o Launchpad per gestire le impronte."
[ "$DO_PAM" = 1 ]    && echo "  • sudo: apri un Terminale e prova  sudo echo ok  (appoggia il dito)."
[ "$DO_UNLOCK" = 1 ] && echo "  • Sblocco schermo: concedi l'Accessibilita' sopra, poi blocca (Ctrl+Cmd+Q)."
echo "  • Disinstallazione:  bash \"$HERE/uninstall.sh\""
