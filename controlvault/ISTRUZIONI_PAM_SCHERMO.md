# Impronta per lo SBLOCCO SCHERMO — installazione sicura

Avvertenze oneste:
- Alla schermata di blocco NON vedrai scritte: appoggi il dito quando risvegli lo schermo;
  se entro ~8s non sblocca, digiti la password (sempre valida come fallback).
- Lo sblocco gira dentro SecurityAgent (sandbox): POTREBBE impedire al modulo di accedere
  all'USB. In quel caso il fingerprint non parte, ma la password funziona come sempre.
- Hai un solo account admin: usa SEMPRE l'auto-ripristino qui sotto quando testi.

## STEP A — shell root + AUTO-RIPRISTINO (rete di sicurezza)
In un terminale apri una shell root:
    sudo -s
Tieni questa shell pronta. L'installer salva un backup; se dopo il test restassi bloccato,
l'auto-ripristino (STEP C) rimette il file com'era da solo dopo 2 minuti.

## STEP B — installa
    cd ~/usbcfg/tools
    sudo bash install_pam_screensaver.sh
Mostra /etc/pam.d/screensaver con la riga `auth sufficient .../pam_cvfp.so 8` in cima.
ANNOTA il percorso del backup stampato (serve allo STEP C).

## STEP C — arma l'auto-ripristino PRIMA di bloccare (nella shell root dello STEP A)
Sostituisci BACKUP col percorso stampato dall'installer, poi:
    ( sleep 120; cp BACKUP /etc/pam.d/screensaver; echo "RIPRISTINATO" ) &
Così, qualunque cosa accada, dopo 2 minuti lo sblocco torna alla password normale.
Se il test va bene, annulla l'auto-ripristino:   kill %1   (o chiudi la shell root).

## STEP D — prova lo sblocco
Blocca lo schermo:  Ctrl+Cmd+Q  (o menu Apple -> Blocca schermo).
Risveglia e APPOGGIA IL DITO registrato. Dovrebbe sbloccare senza password.
Se non succede entro ~8s, digita la password: sei comunque dentro.

## Esito
- Sblocca col dito  -> perfetto, poi `kill %1` per disarmare l'auto-ripristino, e sei a posto.
- NON sblocca ma la password sì -> la sandbox di SecurityAgent blocca il modulo: su questo
  sistema lo sblocco a impronta non e' possibile. Disinstalla:
      sudo sed -i '' '/pam_cvfp/d' /etc/pam.d/screensaver
  (sudo con impronta resta comunque funzionante e indipendente.)

## Nota
Il modulo e' lo stesso di sudo (aggiornato per accettare il timeout 8s). sudo continua a
funzionare col suo timeout di default.
