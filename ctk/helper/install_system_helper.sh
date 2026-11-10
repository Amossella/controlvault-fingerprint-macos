#!/bin/bash
# Installa l'helper impronta del token come LaunchDaemon di SISTEMA (root), così
# è disponibile anche al loginwindow (login al boot / logout), non solo in sessione.
# Sostituisce l'eventuale LaunchAgent utente (stesso Mach service).
#
# Eseguire con sudo:  sudo ctk/helper/install_system_helper.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
UID_REAL="$(stat -f %u /dev/console)"   # utente loggato alla GUI

if [ "$(id -u)" != "0" ]; then echo "Esegui con sudo."; exit 1; fi

echo "== 1) binario in /usr/local/libexec (root-owned) =="
mkdir -p /usr/local/libexec
cp "$HERE/fphelper" /usr/local/libexec/fphelper
chown root:wheel /usr/local/libexec/fphelper
chmod 755 /usr/local/libexec/fphelper

echo "== 2) rimuovo il LaunchAgent utente (se presente) =="
launchctl bootout "gui/$UID_REAL/com.cvfp.fphelper" 2>/dev/null || true
rm -f "/Users/$(id -un $UID_REAL)/Library/LaunchAgents/com.cvfp.fphelper.plist" 2>/dev/null || true

echo "== 3) installo il LaunchDaemon di sistema =="
cp "$HERE/com.cvfp.fphelper.system.plist" /Library/LaunchDaemons/com.cvfp.fphelper.plist
chown root:wheel /Library/LaunchDaemons/com.cvfp.fphelper.plist
chmod 644 /Library/LaunchDaemons/com.cvfp.fphelper.plist

echo "== 4) carico il daemon =="
launchctl bootout system/com.cvfp.fphelper 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.cvfp.fphelper.plist
launchctl print system/com.cvfp.fphelper 2>/dev/null | grep -E "state|program|endpoints" | sed 's/^/   /' || true

echo "OK. Helper di sistema attivo. Prova un logout o un riavvio: al loginwindow"
echo "seleziona l'utente, quando appare il PIN premi Invio e appoggia il dito."
