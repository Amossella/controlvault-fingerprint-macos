# Frida: trovare il processo giusto e catturare i byte crypto

PROBLEMA: lo script si e' agganciato a HostControlService.exe ma durante l'enroll non ha
catturato nulla. Motivo: la crittografia dell'enroll gira in UN ALTRO processo (quasi
certamente il servizio biometrico di Windows = un svchost.exe che ospita WbioSrvc), che
carica bipdll.dll SOLO mentre fai l'impronta.

================================================================
## PASSO 1 — trova il processo giusto (durante un enroll)
================================================================
1. Apri Windows Hello: Impostazioni -> Account -> Opzioni di accesso -> Impronta digitale.
2. Avvia un ENROLL (clic "Configura"/"Aggiungi"). Quando ti chiede di appoggiare il dito,
   LASCIA LA FINESTRA APERTA A META' (non finire i tocchi).
3. Mentre l'enroll e' in corso, apri una SECONDA PowerShell COME AMMINISTRATORE e lancia:
       tasklist /m bipdll.dll
4. Stavolta dovrebbero comparire PIU' processi (oltre a HostControlService, probabilmente
   un svchost.exe con un PID). Annota NOME + PID di tutti.
   (Se compare solo HostControlService, vedi PASSO 3 in fondo.)

================================================================
## PASSO 2 — aggancia il processo giusto e cattura
================================================================
Con il PID del processo che fa l'enroll (es. svchost.exe PID 1234), in PowerShell ADMIN:

    cd C:\cv
    frida -p 1234 -l frida_hook.js -o crypto_log.txt

- Devono comparire le righe "[+] hook: advapi32.dll!CryptHashData ..." e "[*] Hook pronti".
- ORA rifai l'ENROLL da capo (rimuovi l'impronta e configurala di nuovo, 4 tocchi).
- Alla fine Ctrl+C per fermare.
- Il file crypto_log.txt ora dovrebbe contenere i blocchi "=== CryptHashData ...",
  "=== CryptEncrypt PLAINTEXT ... / CIPHERTEXT ...", "=== CryptSetKeyParam KP_IV ...", ecc.
- Copialo in ~/Downloads/ sul Mac e scrivimi "ho il log crypto".

================================================================
## PASSO 3 — se con -p 1234 Frida non riesce ad agganciare
================================================================
Il servizio biometrico gira come SYSTEM; se Frida da' errore di accesso/permessi:
- Assicurati che PowerShell sia "come amministratore".
- Prova ad agganciare per nome del servizio:
      frida -n svchost.exe -l frida_hook.js -o crypto_log.txt
  (se ci sono tanti svchost, usa il -p col PID giusto del passo 1).
- Se proprio non si aggancia (processo protetto), dimmelo: c'e' un'altra strada
  (agganciare la sessione all'AVVIO del servizio ControlVault, o riavviare il servizio
  con Frida gia' attaccato). Te la scrivo in base all'errore esatto.

================================================================
## Note
- Serve UNA sola cattura buona con dentro le chiamate crypto.
- ncrypt "non trovata" nel log precedente = OK, conferma che si usa il percorso RSA legacy.
- La chiave pubblica del chip ce l'ho gia' (device_rsa_modulus.bin): dal log mi servono
  cosa viene hashato (nonce -> session key), l'IV, e input/output di CryptEncrypt (formato comando).
