# Sessione cifrata ControlVault — schema (dal reverse di bipdll.dll)

Fonte: bipdll.dll (driver Windows, PE x64), funzione cvhSetUpSecureSession @~0x39c00.
Sorgente originale: src\BCMIDll\BCMILib_Src\CVUsrLib.c (stesso CVUsrLib del Linux, ma qui
con la crittografia VERA; su Linux era svuotata).

## Tipo di crittografia: STANDARD (Suite B), non custom
Primitive: ECDH P-256 (key agreement) + RSA (autenticazione) + AES + HMAC-SHA256.
Due implementazioni nel binario: MSCAPI_* (CryptoAPI legacy) e MSCNG_* (CNG/BCrypt moderno).
=> ricostruibile con OpenSSL.

## Flusso di cvhSetUpSecureSession (dall'ordine delle funzioni chiamate)
1. GetCVPublicKey (0x23)            -> il device manda la sua chiave pubblica + materiale
2. MSCAPI_VerifyRSASignature       -> verifica la chiave del device (firma RSA) = autentica il chip
3. MSCNG_GenerateHostECCKey        -> l'host genera coppia ECDH P-256 effimera
   (path legacy: MSCAPI_GenerateRandom + MSCAPI_EncryptHostNonce)
4. GetHostEncryptNonce (0x24)      -> manda al device la pubkey ECC / nonce cifrato dell'host
5. MSCNG_GenerateSessionHMACKey        -> deriva chiave HMAC di sessione
   MSCNG_GenerateSessionEncryptionKey  -> deriva chiave AES di sessione
   (dal segreto condiviso ECDH)
6. comandi successivi: cvhEncryptCmd (AES) + HMAC (MSCAPI_GenerateSecureSessionHMAC)

## Cosa serve ancora (parametri esatti, da disassemblare)
- curva/formato ECC (P-256 confermato), formato della chiave del device nel 0x23
- la derivazione esatta: segreto ECDH -> chiave AES + chiave HMAC (quale KDF/hash)
- modalita' AES (CBC/CTR/ECB) e layout dell'HMAC sui comandi
- formato del blocco 0x24 (256B): cosa contiene (pubkey host + firma + nonce)
Funzioni da leggere: MSCNG_GenerateHostECCKey, MSCNG_GenerateSessionEncryptionKey,
MSCNG_GenerateSessionHMACKey, MSCNG_EncryptHostNonce, cvhEncryptCmd.

## Primitive CONFERMATE (CNG di Windows, caricate via GetProcAddress @0x1fdc0)
- NCryptSecretAgreement  -> segreto condiviso ECDH (P-256)
- NCryptDeriveKey        -> KDF: dal segreto ECDH deriva le chiavi di sessione
- BCryptEncrypt/Decrypt  -> AES sui comandi
- BCryptCreateHash/HashData -> SHA256 / HMAC
- CryptImportPublicKeyInfo + CertOpenSystemStoreW + NCryptVerifySignature -> verifica cert chip
Funzioni crypto reali in CVCapiSession.c (0x1d860-0x1f8f0); costruzione blob 0x24 in
"CV secure session blob" (0x204a0/0x20b50/0x20e80). Equivalente OpenSSL/Python:
ECDH SECP256R1 + KDF (SP800-56A Concat o hash, da confermare) + AES + HMAC-SHA256.

## Parametri byte-esatti estratti (2026-11-08)
- ECDH: NCryptSecretAgreement chiamato a 0x3a3a8 (dentro cvhSetUpSecureSession), curva ECDH_P256.
- KDF: NCryptDeriveKey, arg pwszKDF = L"HASH" (BCRYPT_KDF_HASH), hash = L"SHA1",
  con parametro "Secret" (prepend/append = verosimilmente i nonce host/device).
  => chiave_sessione = KDF-HASH(SHA1) del segreto condiviso ECDH.
  (2 call NCryptDeriveKey a 0x20a78/0x20af7 = query dimensione + derivazione reale.)
- Globali puntatori crypto mappati in glob_map.json; call site risolti via win_re.
Ancora da estrarre: contenuto esatto di Secret prepend/append, dimensione chiavi, split
enc/HMAC, modo AES + IV, layout HMAC, formato byte del blob 0x24.

## Stato e lavoro residuo (onesto)
Schema e primitive COMPLETAMENTE identificati: e' crittografia standard, ricostruibile.
Resta da estrarre dal disassemblato i parametri byte-esatti: tipo di KDF e input, modo AES
(CBC/CTR) + IV, layout HMAC, formato del blocco 0x24. Le primitive sono chiamate via puntatori
(GetProcAddress), quindi il disassemblo e' piu' laborioso. Poi: implementare in controlvault.py
e testare l'handshake 0x23/0x24 dal vivo. E' un progetto di RE+sviluppo serio (piu' sessioni),
ma tecnicamente alla portata. Strumenti: win_re/pemap.py, bipdll.dll in win_re/.

## PERCORSO ATTIVO = RSA (MSCAPI), non ECDH — verificato dalle catture (2026-11-08)
Il blocco 0x24 e' 256B = RSA-2048 (ECDH P-256 sarebbe 64B). Quindi le catture usano il
percorso MSCAPI/RSA (il percorso ECDH/MSCNG e' alternativo, non usato qui).
- Chiave pubblica del chip = i 256B statici della risposta 0x23, letti LITTLE-ENDIAN
  = modulo RSA-2048 valido (2048 bit, dispari). Salvata in win_re/device_rsa_modulus.bin.
  Esponente: probabile 0x10001 (da confermare). Il device nonce = ~60B dopo i 256B + info.
- 0x24 = MSCAPI_EncryptHostNonce (CVCapiSession.c): CryptAcquireContext -> CryptImportKey
  (chiave RSA chip) -> CryptEncrypt (nonce host). CryptEncrypt RSA = PKCS#1 v1.5, output LE.
  => 0x24 = RSA_PKCS1v15( host_nonce, device_pubkey ) little-endian.
- chiave di sessione (enc + HMAC) = da MSCAPI_GenerateSessionEncKey/HMACKey: hash di
  host_nonce + device_nonce (hash/ordine da confermare).
Da implementare: generare host_nonce, 0x24 = RSA-encrypt (PKCS1) verso device_pubkey, inviarlo,
derivare chiave di sessione, HMAC/AES sui comandi. RSA-encrypt e' standard (OpenSSL).

## Derivazione chiave di sessione (2026-11-08)
MSCAPI_GenerateSessionEncKey/HMACKey usano hash CryptoAPI: CryptCreateHash(ALGID) ->
CryptHashData(nonce) -> CryptGetHashParam(HP_HASHVAL) = output hash usato come chiave.
ALGID letto dal disasm @0x9cfc: mov edx, 0x8004 = CALG_SHA1. => chiave sessione = SHA1(nonce),
20 byte. Due blocchi hash (0x9ccb, 0x9f15) = enc key + HMAC key.
=> chiave_sessione = SHA1( host_nonce + device_nonce )  [concatenazione/ordine da confermare].

## HANDSHAKE RICOSTRUITO (stato)
1. 0x23 -> device RSA-2048 pubkey (256B LE) + device nonce (~60B)
2. host genera nonce casuale
3. 0x24 = RSA_PKCS1v15(host_nonce, device_pubkey) little-endian
4. session key = SHA1(host_nonce + device_nonce)
5. comandi: HMAC (+ forse AES) con la session key
RESTA: concatenazione/ordine esatti dei nonce, dimensione nonce, layout HMAC sui comandi
(su quali byte, quale chiave), eventuale AES. Poi implementare e testare dal vivo.
Tutto standard (RSA PKCS1 + SHA1/HMAC) -> OpenSSL. Chiave chip in win_re/device_rsa_modulus.bin.

## Handshake DAL VIVO (2026-11-08)
Dopo firmware 4.12 + rimozione kext usbcfgfix: device nativo a config 1, bulk OK (il firmware
ha corretto il bug di enumerazione; il kext non serve piu' ed era diventato dannoso).
Test handshake (tools/cvcrypto.py): init ok; 0x23 -> status 0, chiave chip RSA-2048 valida,
handle 0x14019b8c; 0x24 = RSA-PKCS1v1.5(nostro nonce) LE -> status 0 (accettato a livello envelope).
NOTA: 0x23 risposta col nuovo firmware ha layout diverso dalle vecchie catture (device material
in gran parte zero + pochi byte finali) -> la posizione del device nonce va riconfermata.
MANCA per validare: la session key esatta (quali nonce/ordine/hash) e l'HMAC sui comandi
(MSCAPI_GenerateSecureSessionHMAC, cvhEncryptCmd) per inviare un comando sicuro accettato.
E' l'ultimo miglio, e va debbuggato "alla cieca" (il device non da' feedback parziale).

## Protezione dei comandi sicuri (2026-11-08) — schema COMPLETO
cvhEncryptCmd (CVUsrLib.c) chiama: MSCAPI_EncryptParamBlob (AES) + MSCAPI_GenerateSecureSessionHMAC (HMAC).
AES: CryptSetKeyParam con dwParam=1=KP_IV => AES-CBC con IV. Chiave = SHA1-derivata (20B).
=> comando_sicuro = AES-CBC( param_blob, session_enc_key, IV ) + HMAC( session_hmac_key ).

## SCHEMA CRITTOGRAFICO COMPLETO (riepilogo)
1. 0x23: device -> RSA-2048 pubkey (256B LE) + device material/nonce.
2. host genera nonce; 0x24 = RSA-PKCS1v1.5(host_nonce) LE.
3. session_enc_key = SHA1(nonce...), session_hmac_key = SHA1(nonce...).  (CALG_SHA1)
4. ogni comando sicuro = AES-CBC(dati, enc_key, IV) + HMAC(hmac_key).
Tutte primitive STANDARD (RSA PKCS1, SHA1, AES-CBC, HMAC) -> OpenSSL/Python.

## Ultimo miglio (byte-perfect + debug alla cieca)
Per un comando sicuro ACCETTATO servono i dettagli byte-esatti, ognuno un passo di reverse:
- ordine/concatenazione esatti dei nonce per enc_key e hmac_key, e dove sta il device nonce
  nel 0x23 del NUOVO firmware (layout diverso dalle catture vecchie);
- IV esatto (da dove), e se AES e' su tutto il blob o parte;
- algoritmo e layout HMAC (SHA1 vs SHA256, su quali byte, dove si appende);
- formato byte del campo data del comando sicuro.
Poi debug alla cieca sul device (nessun feedback parziale). Fattibile ma oneroso/incerto.

## Nonce individuati dal vivo (nuovo firmware, 2026-11-08)
Risposta 0x23 (320B): [0..255]=chiave RSA statica, [256..295]=zero, [296..315]=DEVICE NONCE
(20B, variabile a ogni handshake), [316..319]=zero. Host nonce = 20B (nel 0x23 request).
=> session keys = SHA1( host_nonce[20] + device_nonce[20] ), ordine enc/hmac da fissare (2 varianti).
Handle incrementa a ogni 0x23 (14019bf8, 14019c64, 14019cd0...).
Resta: ordine esatto nonce per enc/hmac key; formato comando sicuro (AES-CBC + HMAC: le
dimensioni dati nelle catture Windows non seguono un semplice 16k+20, probabile header + padding);
IV; poi debug alla cieca. Spazio di ricerca molto ridotto ma non banale.

## Formato comando sicuro (indizi da cvhEncryptCmd, 2026-11-08)
Nell'assemblaggio: size += 0x14 (20B = HMAC-SHA1) e 0x20 (32B) in punti diversi -> comando
sicuro = [header][AES-CBC(dati)][HMAC-SHA1 20B]. Funzioni interne: 0x4d36c (AES/blob),
0x1fbe0 (HMAC), 0x21500. Layout byte-esatto (header, dove inizia l'HMAC, IV) ancora da tracciare.
ULTIMO MIGLIO = reverse byte-perfetto di cvhEncryptCmd + debug alla cieca sul device.

## CRITTOGRAFIA CRACCATA E VERIFICATA AL BYTE (cattura Frida, 2026-11-08)
Dal log Frida di svchost (WbioSrvc) durante un enroll reale, con byte veri:
- Chiave chip: CryptImportKey PUBLICKEYBLOB "RSA1", esponente 0x10001, modulo = i 256B del 0x23 (LE). CONFERMATO.
- 0x24 = CryptEncrypt(plaintext=host_nonce 20B) -> 256B = RSA-PKCS1v1.5 LE. CONFERMATO.
- AES-128 key = SHA1( device_nonce[20] || host_nonce[20] )[:16].  VERIFICATO (==chiave importata 0e66=CALG_AES_128).
- HMAC key = SHA1( b"CV secure session blob\x00" ) = dbac7907...  COSTANTE. VERIFICATO.
- Comando sicuro: header 44B con IV a offset 24..39; mac=HMAC-SHA1(hmac_key, header||data);
  plaintext = data || mac(20) || zero-pad(16); ciphertext = AES-128-CBC(plaintext,aes_key,IV)+PKCS7.
  total_len = 44 + len(ciphertext). VERIFICATO: la mia AES-CBC riproduce ESATTAMENTE il
  ciphertext catturato, e HMAC-SHA1 riproduce il mac incluso nel plaintext.
Implementato in tools/cvcrypto.py. Device nonce @296, host nonce 20B, pycryptodome richiesto.
PROSSIMO: provare un comando sicuro vero sul device (open/enable in sessione cifrata).

## ✅ SESSIONE CIFRATA FUNZIONANTE E PROVATA SUL DEVICE (2026-11-08)
Handshake 0x23/0x24 + comando sicuro costruiti da cvcrypto.py, testati dal vivo su macOS:
- HMAC+AES corretti  -> status 0 + risposta cifrata (12B)  [ACCETTATO]
- HMAC sbagliato      -> status 0x0f  [RIFIUTATO]
- AES sbagliato       -> status 0x0f  [RIFIUTATO]
=> il chip verifica la crittografia e accetta SOLO i comandi cifrati correttamente.
IL MURO CRITTOGRAFICO E' ABBATTUTO. La crittografia e' completa, verificata e funzionante.
Resta "solo" (sviluppo normale): ricostruire enroll (open->enable->capture->update->commit)
e verify (cv_identify) DENTRO la sessione cifrata, poi PAM per sudo/login.
