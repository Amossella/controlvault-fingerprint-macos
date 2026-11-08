# Impronta per `sudo` — installazione sicura

Idea: digiti `sudo ...`, appoggi il dito, sei autenticato. Se l'impronta non va,
sudo chiede la **password** come sempre. Nessuna password viene memorizzata.

## STEP 1 — prova l'helper da solo (nessuna modifica al sistema)
    /usr/local/bin/python3 ~/usbcfg/tools/fpauth.py; echo "exit=$?"
- Appoggia il dito REGISTRATO → deve stampare "riconosciuta ✓" e `exit=0`.
- Un dito diverso → "non riconosciuta" e `exit=1`.
Se qui exit=0 col dito giusto, procedi.

## STEP 2 — rete di sicurezza (IMPORTANTE)
Apri un SECONDO terminale e lascia aperta una shell root per tutta la durata del test:
    sudo -s
Se qualcosa va storto con sudo nel primo terminale, da QUESTA shell puoi ripristinare:
    cp /etc/pam.d/sudo.bak.* /etc/pam.d/sudo        # (l'ultimo backup)
    # oppure:
    sed -i '' '/pam_cvfp/d' /etc/pam.d/sudo

## STEP 3 — installa
Nel primo terminale:
    cd ~/usbcfg/tools
    sudo bash install_pam.sh
Mostra il nuovo /etc/pam.d/sudo con la riga `auth sufficient .../pam_cvfp.so` in cima.

## STEP 4 — prova sudo con l'impronta
    sudo -k            # dimentica l'autenticazione recente
    sudo echo ok
- Deve comparire "[impronta] appoggia il dito sul sensore..." → appoggi il dito → `ok`.
- Se NON appoggi il dito (o dito sbagliato): dopo ~12s chiede la password normale.

## Disinstallare
    sudo sed -i '' '/pam_cvfp/d' /etc/pam.d/sudo
    sudo rm -f /usr/local/lib/pam_cvfp.so

## Note
- La riga e' `sufficient`: impronta OK → sudo passa; impronta KO/timeout → password.
  Non puoi restare bloccato fuori: la password funziona sempre.
- Il modulo lancia `fpauth.py` come root durante l'auth; usa gli handle in
  ~/usbcfg/controlvault/mac_template.json (le impronte registrate con fpenroll.py).
