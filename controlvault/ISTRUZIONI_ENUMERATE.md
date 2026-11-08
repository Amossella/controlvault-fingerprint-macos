# Catturare ENUMERATE + LOAD TEMPLATE (Windows Frida)

Obiettivo: vedere i comandi che il servizio biometrico manda quando CARICA i template nel
chip (enumerate objects + load). Servono per trovare l'handle del template registrato su macOS.
Lo script frida_hook.js cattura gia' tutto (sono comandi cifrati via CryptEncrypt): basta
innescare il ricaricamento dei template MENTRE Frida e' agganciato.

## Passi
1. PowerShell COME AMMINISTRATORE in C:\cv.
2. Trova il PID del servizio biometrico:
       tasklist /m bipdll.dll
   (svchost.exe di WbioSrvc; se non c'e', fai prima un Win+L + sblocco impronta per caricarlo)
3. Aggancia Frida e AVVIA il log:
       frida -p <PID> -l frida_hook.js -o enum_log.txt
   Aspetta "[*] Hook pronti".
4. Ora FORZA il ricaricamento dei template (scegli UNA, in ordine di preferenza):
   a) Gestione Dispositivi -> categoria "Dispositivi biometrici" (o "Security devices" /
      "Dell ControlVault"): tasto destro sul lettore -> DISABILITA, attendi 3s, poi ABILITA.
   b) In alternativa: Win+L (blocca) e SBLOCCA con l'impronta 2-3 volte.
   Fai entrambe se puoi: servono i comandi di (ri)caricamento dei template.
5. Dopo il riconoscimento, Ctrl+C per fermare Frida.
6. Copia enum_log.txt sul Mac (/Volumes/HDD/cv/ o ~/Downloads) e scrivimi "ho il log enum".

## Cosa cerco nel log
- Un comando con risposta che elenca piu' HANDLE di oggetti (i template) -> enumerate objects
- Eventuali comandi che trasferiscono un BLOB template nel chip -> load template
- Confermero' che corrisponde all'handle 0x5dc14c gia' visto nel verify.

## Nota
Se disabilitando il lettore Frida si stacca (il servizio si riavvia), rifai dal passo 2
dopo aver riabilitato il lettore: il PRIMO sblocco impronta dopo il riavvio del servizio
fa l'enumerate+load, ed e' quello che ci serve. Tieni Frida agganciato durante quel primo sblocco.
