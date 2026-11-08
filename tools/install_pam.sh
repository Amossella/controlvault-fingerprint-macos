#!/bin/bash
# Installa il modulo impronta per sudo, IN SICUREZZA.
# Esegui:  sudo bash install_pam.sh
# La riga viene messa come 'sufficient' PRIMA della password: se l'impronta
# fallisce, sudo chiede la password come sempre. Backup automatico di /etc/pam.d/sudo.
set -e
if [ "$(id -u)" != "0" ]; then echo "Esegui con: sudo bash install_pam.sh"; exit 1; fi

SRC="$(cd "$(dirname "$0")" && pwd)/pam_cvfp.so"
MOD="/usr/local/lib/pam_cvfp.so"
PAMSUDO="/etc/pam.d/sudo"
LINE="auth       sufficient     /usr/local/lib/pam_cvfp.so"

[ -f "$SRC" ] || { echo "manca $SRC (compila prima: clang -bundle -o pam_cvfp.so pam_cvfp.c -lpam)"; exit 1; }

BAK="${PAMSUDO}.bak.$(date +%Y%m%d%H%M%S)"
cp "$PAMSUDO" "$BAK"
echo "Backup: $BAK"

mkdir -p /usr/local/lib
cp "$SRC" "$MOD"; chown root:wheel "$MOD"; chmod 644 "$MOD"
echo "Modulo installato: $MOD"

if grep -q pam_cvfp "$PAMSUDO"; then
  echo "Riga gia' presente in $PAMSUDO."
else
  awk -v line="$LINE" 'NR==1{print; print line; next} {print}' "$PAMSUDO" > "${PAMSUDO}.new"
  cat "${PAMSUDO}.new" > "$PAMSUDO"
  rm -f "${PAMSUDO}.new"
  echo "Riga aggiunta a $PAMSUDO."
fi
echo "=============================="
cat "$PAMSUDO"
echo "=============================="
echo "Per DISINSTALLARE:  sudo sed -i '' '/pam_cvfp/d' $PAMSUDO   (oppure ripristina $BAK)"
