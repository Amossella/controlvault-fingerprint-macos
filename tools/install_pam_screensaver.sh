#!/bin/bash
# Aggiunge l'impronta allo SBLOCCO SCHERMO (/etc/pam.d/screensaver), in sicurezza.
# Esegui:  sudo bash install_pam_screensaver.sh
# Riga 'sufficient' PRIMA della password: impronta OK -> sblocca; KO/timeout -> password.
set -e
if [ "$(id -u)" != "0" ]; then echo "Esegui con: sudo bash install_pam_screensaver.sh"; exit 1; fi

SRC="$(cd "$(dirname "$0")" && pwd)/pam_cvfp.so"
MOD="/usr/local/lib/pam_cvfp.so"
PAMSS="/etc/pam.d/screensaver"
LINE="auth       sufficient     /usr/local/lib/pam_cvfp.so 8"   # timeout 8s

[ -f "$SRC" ] || { echo "manca $SRC"; exit 1; }

BAK="${PAMSS}.bak.$(date +%Y%m%d%H%M%S)"
cp "$PAMSS" "$BAK"
echo "Backup: $BAK"

mkdir -p /usr/local/lib
cp "$SRC" "$MOD"; chown root:wheel "$MOD"; chmod 644 "$MOD"   # aggiorna il modulo
echo "Modulo aggiornato: $MOD"

if grep -q pam_cvfp "$PAMSS"; then
  echo "Riga gia' presente."
else
  awk -v line="$LINE" 'NR==1{print; print line; next} {print}' "$PAMSS" > "${PAMSS}.new"
  cat "${PAMSS}.new" > "$PAMSS"; rm -f "${PAMSS}.new"
  echo "Riga aggiunta a $PAMSS."
fi
echo "=============================="
cat "$PAMSS"
echo "=============================="
echo "Ultimo backup: $BAK"
echo "Disinstalla:  sudo sed -i '' '/pam_cvfp/d' $PAMSS"
