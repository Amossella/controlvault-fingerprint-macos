#!/bin/bash
# Installa il demone di sblocco come LaunchAgent (avvio automatico al login).
# Utente, NON sudo:   bash install_unlock_agent.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PY="${CVFP_PYTHON:-/usr/local/bin/python3}"
mkdir -p "$HOME/Library/LaunchAgents"
# prima l'arbitro (unico proprietario del lettore), poi il demone che lo usa
for NAME in com.cvfp.arbiter com.cvfp.unlock; do
  DST="$HOME/Library/LaunchAgents/$NAME.plist"
  # i .plist del repo sono modelli: qui si inseriscono python e cartella reali
  sed -e "s|__PYTHON__|$PY|g" -e "s|__ROOT__|$ROOT|g" "$HERE/$NAME.plist" > "$DST"
  launchctl unload "$DST" 2>/dev/null || true
  launchctl load -w "$DST"
done
DST="$HOME/Library/LaunchAgents/com.cvfp.unlock.plist"
echo "LaunchAgent installato e avviato: $DST"
echo "Log:  tail -f $ROOT/controlvault/fpunlock.log   (arbitro: fparbiter.log)"
echo
echo "Se il log dice 'PERMESSO ACCESSIBILITA' MANCANTE':"
echo "  Impostazioni -> Privacy e sicurezza -> Accessibilita' -> '+' ->"
echo "  Cmd+Shift+G e incolla:"
echo "     $("$PY" -c 'import os,sys;print(os.path.realpath(sys.executable))')"
echo "  abilita l'interruttore, poi:  launchctl kickstart -k gui/\$(id -u)/com.cvfp.unlock"
echo
echo "Per DISATTIVARE l'avvio automatico:"
echo "  launchctl unload ~/Library/LaunchAgents/com.cvfp.unlock.plist"
echo "  rm ~/Library/LaunchAgents/com.cvfp.unlock.plist"
