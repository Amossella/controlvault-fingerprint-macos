#!/bin/bash
# =====================================================================
#  ControlVault Fingerprint for macOS — disinstallazione
#  Rimuove: modulo PAM da sudo, demone di sblocco, app FP Manager e
#  (a richiesta) la password dal Keychain. NON tocca le impronte nel chip.
#
#  Uso:   bash uninstall.sh
# =====================================================================
set -u
say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "   \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "   \033[33m!\033[0m %s\n" "$*"; }

say "Demone di sblocco e arbitro del lettore"
for NAME in com.cvfp.unlock com.cvfp.arbiter; do
  PL="$HOME/Library/LaunchAgents/$NAME.plist"
  if [ -f "$PL" ]; then
    launchctl unload "$PL" 2>/dev/null || true
    rm -f "$PL" && ok "LaunchAgent rimosso: $NAME"
  else ok "nessun LaunchAgent: $NAME"; fi
done
rm -f "$(cd "$(dirname "$0")/.." && pwd)/controlvault/arbiter.sock" /tmp/cvfp-arbiter.sock

say "Modulo PAM per sudo (richiede password admin)"
if grep -q pam_cvfp /etc/pam.d/sudo 2>/dev/null; then
  sudo sed -i '' '/pam_cvfp/d' /etc/pam.d/sudo && ok "riga rimossa da /etc/pam.d/sudo"
else ok "nessuna riga in /etc/pam.d/sudo"; fi
if [ -f /usr/local/lib/pam_cvfp.so ]; then
  sudo rm -f /usr/local/lib/pam_cvfp.so && ok "modulo rimosso"
fi

say "App FP Manager"
for A in "/Applications/FP Manager.app" "$HOME/Desktop/FP Manager.app"; do
  [ -d "$A" ] && rm -rf "$A" && ok "rimossa: $A"
done

say "Password nel Keychain"
if security find-generic-password -s cv-fp-unlock -w >/dev/null 2>&1; then
  read -r -p "   Rimuovere la password di login dal Keychain? [s/N] " ans
  if [ "${ans:-N}" = "s" ] || [ "${ans:-N}" = "S" ]; then
    security delete-generic-password -s cv-fp-unlock >/dev/null 2>&1 && ok "rimossa"
  else warn "lasciata nel Keychain"; fi
else ok "nessuna password salvata"; fi

say "Fatto"
echo "  • Le impronte registrate nel chip NON sono state toccate."
echo "  • I file del progetto restano in $(cd "$(dirname "$0")/.." && pwd)."
