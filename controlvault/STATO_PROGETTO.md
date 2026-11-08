# ControlVault / BCM5880 su macOS — stato del progetto (handoff)

Lettore impronte Dell ControlVault2 / Broadcom BCM5880 (USB 0a5c:5834), Dell Latitude 5580
Hackintosh, macOS. Obiettivo: enroll/verify impronta per login/sudo.

## RISOLTO e funzionante
- **USB**: col firmware ControlVault 4.12.x (aggiornato da Windows) il device funziona
  NATIVAMENTE su macOS a config 1, bulk transfer OK, SENZA alcun kext. (Il vecchio kext
  usbcfgfix serviva al firmware vecchio ed e' stato rimosso perche' ora dannoso.)
- **Protocollo** completamente decodificato: envelope, formato comandi, mappa opcode,
  codici di stato. Vedi SESSION.md, ENROLL_PROTOCOL.md.
- **Scansione impronta**: funziona (su Linux col driver patchato: 4 stadi "passed").
- **Driver**: libreria Python controlvault.py (trasporto libusb, sessione, comandi).

## Causa del blocco (enroll/verify) — compresa a fondo
Il chip accetta la SCANSIONE in chiaro, ma per SALVARE (commit) e VERIFICARE un'impronta
pretende la SESSIONE CIFRATA. Il driver open Linux la salta -> commit fallisce (0x8d),
bug noto community. Windows fa la cifratura -> funziona.

## Crittografia della sessione — SCHEMA COMPLETO (reverse di bipdll.dll, driver Lynx/5880)
Primitive STANDARD (Suite B/legacy): RSA-2048, SHA1, AES-CBC, HMAC. Due percorsi
(MSCAPI legacy e MSCNG/CNG); le catture usano il percorso RSA/MSCAPI.
1. 0x23: device -> chiave pubblica RSA-2048 (256B della risposta, LITTLE-ENDIAN = modulo;
   salvata in win_re/device_rsa_modulus.bin) + DEVICE NONCE (20B a offset 296..315).
   Host manda un host nonce (20B) nel 0x23 request.
2. 0x24 = RSA-PKCS1v1.5( host_nonce, device_pubkey ), little-endian.  [implementato in cvcrypto.py]
3. session enc key, hmac key = SHA1( host_nonce[20] + device_nonce[20] )  (CALG_SHA1).
4. comando sicuro = [header] + AES-CBC(dati, enc_key, IV) + HMAC-SHA1(hmac_key).

Stato handshake: 0x23/0x24 GIRANO sul device (cvcrypto.py), accettati a livello envelope.

## ULTIMO MIGLIO (cosa manca, e come chiuderlo bene)
Mancano i dettagli BYTE-ESATTI del comando sicuro: ordine esatto dei nonce per enc/hmac key,
IV, header, posizione dell'HMAC, su quali byte si calcola. E vanno validati, ma il device
non da' feedback parziale (debug alla cieca) -> indovinare in chat non converge.

METODO GIUSTO per finire (uno dei due):
- A) DEBUGGER sul DLL: agganciare bipdll.dll in esecuzione su Windows (x64dbg) e leggere i
  byte ESATTI che produce (chiave AES, IV, HMAC, buffer del comando) per 1 sessione reale.
  Con quei valori + la chiave del chip, si fissano i parametri e si implementa in cvcrypto.py.
- B) WINE/Windows helper: far eseguire la crittografia direttamente a bipdll.dll (come fa il
  progetto Linux col binario Dell), facendo da ponte USB verso il chip.

## File del progetto (~/usbcfg)
- controlvault/controlvault.py   driver (trasporto, sessione, comandi)
- controlvault/SESSION.md         protocollo + envelope + mappa comandi
- controlvault/ENROLL_PROTOCOL.md sequenza enroll in chiaro (da cattura Linux)
- controlvault/SESSIONE_CIFRATA.md schema crittografico completo (questo e' il cuore)
- tools/cvcrypto.py               RSA-PKCS1v1.5 + SHA1 (handshake, Python puro)
- tools/cv.py, cvproto.py, usbpcap.py, usbmon.py  client, encoder, parser catture
- win_re/pemap.py                 analizzatore PE; bipdll.dll; device_rsa_modulus.bin; glob_map.json
- revault_re/                     reverse del driver Linux (elfmap.py, callgraph.py, SESSION.md)
- linux_capture/                  cattura enroll Linux + log + decodifica

## Riferimenti
Talos ReVault; progetto Linux grosa787/dell-controlvault2-fingerprint-linux.
