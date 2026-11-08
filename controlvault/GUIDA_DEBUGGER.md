# Guida: estrarre i byte esatti della crittografia da bipdll.dll (Windows)

Obiettivo: catturare, durante UN enroll/verify reale in Windows, i valori crypto esatti
(chiave AES, IV, HMAC, cosa viene hashato per la chiave di sessione, il buffer del comando).
Con quei valori chiudo l'implementazione su macOS senza piu' indovinare.

Ci sono due modi: il PIU' SEMPLICE (API Monitor) e quello preciso (x64dbg).
Consiglio di provare prima API Monitor.

================================================================
## MODO 1 (consigliato, facile): API Monitor
================================================================
1. Scarica "API Monitor v2" (rohitab.com), versione 64-bit. E' gratuito.
2. Avvialo COME AMMINISTRATORE.
3. Nel pannello "API Filter" (sinistra), spunta queste categorie/funzioni:
   - Cryptography -> Cryptography (advapi32): CryptImportKey, CryptCreateHash, CryptHashData,
     CryptGetHashParam, CryptDeriveKey, CryptSetKeyParam, CryptEncrypt, CryptDecrypt
   - Cryptography -> CNG (bcrypt/ncrypt): BCryptEncrypt, BCryptDecrypt, NCryptDeriveKey,
     NCryptSecretAgreement, BCryptHashData, BCryptFinishHash
4. Monitora il processo giusto: Menu "Monitor New Process" NON serve; invece usa
   "Monitor Process" e aggancia il servizio biometrico. Il processo che carica bipdll.dll e'
   di solito **svchost.exe (WbioSrvc)** oppure **HostControlService.exe**. Se non sai quale:
   in API Monitor, menu Tools -> Monitor Running Process, cerca il processo che ha caricato
   `bipdll.dll` (colonna Modules) e aggancialo. In alternativa aggancia TUTTI i svchost e filtra dopo.
5. Con il monitor attivo, vai in Impostazioni Windows -> Account -> Opzioni di accesso ->
   Impronta digitale: RIMUOVI l'impronta e fai un NUOVO enroll (i 4 tocchi), poi una verifica.
6. In API Monitor vedrai la lista delle chiamate con i PARAMETRI (clic su una riga mostra i
   buffer in esadecimale). Esporta tutto: File -> Save / Export (formato .apmx o CSV).
7. Portami il file esportato in ~/Downloads/ e scrivimi "ho il log crypto".

Cosa catturo da quel log:
- CryptHashData: i byte hashati (= i nonce, nell'ordine giusto) -> fissa la session key.
- CryptSetKeyParam (KP_IV=1): l'IV dell'AES.
- CryptEncrypt / CryptDecrypt: input e output (= formato del comando sicuro) e handle chiave.
- CryptImportKey: la chiave del chip importata.

================================================================
## MODO 2 (preciso): x64dbg
================================================================
1. Scarica x64dbg (x64dbg.com), usa "x64dbg" (64-bit).
2. File -> Attach -> seleziona il processo che ha caricato bipdll.dll (svchost WbioSrvc o
   HostControlService.exe).
3. Imposta breakpoint sulle API (comando nella barra in basso), uno per riga:
     bp advapi32.CryptImportKey
     bp advapi32.CryptCreateHash
     bp advapi32.CryptHashData
     bp advapi32.CryptSetKeyParam
     bp advapi32.CryptEncrypt
     bp advapi32.CryptDecrypt
   (se usa CNG invece: bp bcrypt.BCryptEncrypt ; bp ncrypt.NCryptDeriveKey ; bp ncrypt.NCryptSecretAgreement)
4. Premi F9 (Run). Vai a fare l'enroll in Windows Hello.
5. Ad OGNI stop, leggi gli argomenti x64 (convenzione: rcx, rdx, r8, r9, poi stack):
   - CryptHashData(hHash=rcx, pbData=rdx, dwDataLen=r8d): nella finestra Dump vai a [rdx],
     seleziona r8d byte -> copia hex. (= cosa viene hashato)
   - CryptSetKeyParam(hKey=rcx, dwParam=edx, pbData=r8, dwFlags=r9d): se edx==1 (KP_IV),
     [r8] per 16 byte = IV.
   - CryptEncrypt(hKey, hHash, Final, dwFlags, pbData=5o arg sullo stack [rsp+28],
     pdwDataLen, dwBufLen): leggi il buffer pbData prima (plaintext) e dopo (ciphertext).
   Annota tutti questi valori.
6. Mandami i valori raccolti.

================================================================
## Nota
Serve UNA sola sessione catturata bene. Con i byte esatti (chiave AES, IV, cosa si hasha per
le chiavi, formato del comando) implemento l'handshake+comando sicuro in cvcrypto.py e lo
testiamo sul device macOS. La chiave pubblica del chip ce l'ho gia' (device_rsa_modulus.bin).
