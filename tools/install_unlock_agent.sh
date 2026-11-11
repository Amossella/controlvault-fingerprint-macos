#!/bin/bash
# Installa il demone di sblocco come LaunchAgent (avvio automatico al login).
# Utente, NON sudo:   bash install_unlock_agent.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME/Library/LaunchAgents"
# prima l'arbitro (unico proprietario del lettore), poi il demone che lo usa
for NAME in com.cvfp.arbiter com.cvfp.unlock; do
  DST="$HOME/Library/LaunchAgents/$NAME.plist"
  cp "$HERE/$NAME.plist" "$DST"
  launchctl unload "$DST" 2>/dev/null || true
  launchctl load -w "$DST"
done
DST="$HOME/Library/LaunchAgents/com.cvfp.unlock.plist"
echo "LaunchAgent installato e avviato: $DST"
echo "Log:  tail -f ~/usbcfg/controlvault/fpunlock.log"
echo
echo "Se il log dice 'PERMESSO ACCESSIBILITA' MANCANTE':"
echo "  Impostazioni -> Privacy e sicurezza -> Accessibilita' -> '+' ->"
echo "  Cmd+Shift+G e incolla:"
echo "     /Library/Frameworks/Python.framework/Versions/3.15/bin/python3.15"
echo "  abilita l'interruttore, poi:  launchctl kickstart -k gui/\$(id -u)/com.cvfp.unlock"
echo
echo "Per DISATTIVARE l'avvio automatico:"
echo "  launchctl unload ~/Library/LaunchAgents/com.cvfp.unlock.plist"
echo "  rm ~/Library/LaunchAgents/com.cvfp.unlock.plist"
