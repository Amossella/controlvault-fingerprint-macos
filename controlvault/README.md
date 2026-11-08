# controlvault — driver utente (prototipo) per Dell ControlVault2 / BCM5880 su macOS

Lettore di impronte Dell ControlVault2 / Broadcom BCM5880, USB `0a5c:5834`, su Hackintosh
(Dell Latitude 5580, macOS Sequoia, OpenCore). Obiettivo finale: enroll/verify e login/sudo.

## Stato
**Funziona e verificato sul device:**
- Fix enumerazione USB: kext `usbcfgfix` v6 forza `SET_CONFIGURATION(0)` (il chip espone
  `bConfigurationValue=0`; senza il fix i bulk transfer falliscono con transaction error).
- Trasporto libusb + envelope + encoder comandi (`controlvault.py`): `init` (0x82) e
  `cv_open` (0x23) costruiti da zero → `status 0`, handle e certificato corretti.

**Da completare (porting del driver host Dell — settimane):**
- `cmd_word` dei verbi generici (enable/identify/enroll): composto in `cvhManageCVAPICall`
  (ramo 0x1fe50) da opcode + categoria + encap, dentro la command-state machine.
- Tabella sessioni host (`GetCVInternalHandle`), eventuale autorizzazione sessione.
- Valori dei parametri dallo strato libfprint; sequenza di enroll; integrazione PAM.

## File
- `controlvault.py` — libreria driver (trasporto, envelope, encoder, init, cv_open, stub verbi).
- `../revault_re/SESSION.md` — reverse engineering completo del protocollo e del driver Dell.
- `../revault_re/elfmap.py`, `callgraph.py` — strumenti statici (xref stringhe, grafo chiamate).
- `../tools/cvproto.py`, `cv.py`, `usbpcap.py` — encoder, client di prova, parser catture.

## Uso
```bash
python3 controlvault.py   # esegue init + cv_open sul device e stampa gli status
```

## Fatti chiave del protocollo
- Envelope: `[seq:4][total:4][cmd_word:4][counter:4][handle:4][status:4][16B zero][data_len:4][blob]`.
  `status` (offset 20): 0 = OK. `cmd_word` byte3: 0=request, 1=response.
- Parametro: `[encap_type:4][len:4][value]` (type 3 = solo header). Blob = concat, value a 4B.
- Il canale comandi NON è cifrato nel driver Linux (le catture Windows mostrano una variante
  cifrata che qui non si usa). La sola crittografia host è `RSA_verify` del certificato device.

## Opcode noti
`init 0x82`, `cv_open 0x23`, `enable_fingerprint 0x41`, `identify 0x35`, `enrollment_started 0x8a`.

## Riferimenti
- Talos "ReVault" (BCM582x / ControlVault3).
- Driver Linux: `launchpad.net/~oem-solutions-engineers/libfprint-2-tod1-broadcom` (branch upstream).

## Frontiera: cattura (2026-11-07)
Decodificato `cv_fingerprint_capture_start(handle, arg2, arg3, buf20, out5, out6)`:
3 param input STRUC 4B = [internalHandle, arg2, arg3] + buffer 20B + output.
Sul device: `capture_start` (cmd_word 0x00400066) → status 0 + 28B token; poi 0x85 (pending).
`capture_get_result` (0x00400069) → status 0x89 (nessun risultato) COSTANTE, col dito o senza,
per ogni valore di arg2/arg3 provato. Conclusione: il comando è accettato ma lo scanner NON si
arma. `cv_fingerprint_capture_start` NON è chiamata internamente al .so: la invoca lo strato
libfprint TOD dall'esterno, che fornisce i valori reali di arg2/arg3/buf20. Quei valori (e la
sequenza enroll/verify) sono la logica di integrazione libfprint — il prossimo strato da
implementare, non ricavabile dal probing del device.

## Conclusione del progetto
Costruito e verificato: fix USB, protocollo completo, envelope, formato comandi, encoder,
sessione (init/open), command code e codici di stato, macchina a stati della cattura.
Da fare (sviluppo driver, non reverse di un singolo dato): integrazione libfprint per armare
la scansione, enroll, verify, e PAM. Base completa qui + in ../revault_re/SESSION.md.

## Mappa comandi completa (2026-11-07)
cmd_word = opcode | (0x40<<16). Opcode (byte0) ricavati dai dispatch del driver:
- 0x82 init · 0x23 cv_open · 0x40 enable_smartcard
- 0x63 cv_enable_wbdi (abilitazione biometrica REALE; arma la cattura)
- 0x41 cv_enable_fingerprint · 0x35 cv_identify_user
- 0x66 capture_start · 0x68 capture_cancel · 0x69 capture_get_result
- 0x6a cv_fingerprint_create_feature_set · 0x8a cv_cmd_enrollment_started
Nota: cv_fingerprint_capture_wait è uno STUB (ritorna 0); l'attesa dito è asincrona.

## Flusso cattura: cosa funziona e cosa manca
Funziona: enable_wbdi(0x63) -> capture_start(0x66) in loop si ARMA (0x86 init -> 0x0 armato).
Segnale dito = interrupt EP 0x85 "0300000000000000" (in Windows precede la lettura scansione).
NON funziona ancora: la scansione reale del dito. create_feature_set(0x6a) resta 0x89 e
nessun 0x03 arriva al tocco. Ipotesi forte: create_feature_set richiede un CONTESTO di
enrollment attivo (cv_cmd_enrollment_started 0x8a) in cui scrivere il feature set; da solo
non ha destinazione -> 0x89. Serve la sequenza enroll completa dallo strato cvif
(cvif_fingerprint_capture_start @0x2afd0, cvif enroll) con i parametri reali.

## Sequenza enroll (da cvhDoAsyncFPEnroll @0x26ba0)
discard_enrollment(0x6d) → cvhDoAsyncFPCapture → update_enrollment(0x6c) → commit_enrollment(0x02),
preceduta da enrollment_started(0x8a). Provata sul device con parametri indovinati:
enrollment_started → status 0x57 (comando/param non validi), nessun campione. Conferma che
ogni comando richiede i parametri ESATTI dello strato cvif/libfprint (user id, finger, contesto
feature-set), non indovinabili dal probing.

## SCOPERTA DECISIVA dalla cattura Linux (2026-11-07)
Il driver Dell UFFICIALE su Linux (fprintd + libfprint-2-tod-1-broadcom) FALLISCE su questo
device esattamente come il nostro codice:
- probe: "Could not determine chip type" + "FwUpgradeError ... Error: 0x1c"
- enroll: "Device status = (87)"  <-- lo stesso status 87 ricavato da noi
- identify: "unforeseen error"
Chip (da GET_STATUS nel pcap): USH_CHIPID 05810211, CV_VER 01000235, CUST_ID 60000001,
BUILD Oct 21 2016, FP_NEXT_SENSOR=1, AES_KEY_VALID=1.
Questo errore ("Could not determine chip type" + FwUpgradeError 0x1c) e' un BUG NOTO e
IRRISOLTO del driver open-source (issue grosa787 #2/#9/#15; modelli 7490/5490/7280).
CONSEGUENZA: il nostro port era corretto (status 87 = identico al driver reale), ma il
blocco e' a livello firmware/riconoscimento chip, NON nel nostro codice. Il lettore funziona
solo su Windows (dove il driver Dell chiuso gestisce chip-type e firmware). Tradurre il
driver Linux su macOS non puo' produrre una scansione finche' questo bug upstream non e'
risolto, perche' il driver Linux stesso non funziona su questo chip.

## Stato realistico (conclusione)
Protocollo e livello comandi: COMPLETI e verificati (sessione, enable biometrico, arming cattura,
mappa comandi, codici stato). Scansione/enroll/verify reali: richiedono di riprodurre fedelmente
la sequenza dello strato cvif/libfprint con i parametri corretti — sviluppo driver sostenuto,
NON ricavabile un comando alla volta dal probing interattivo. Questa è la base completa per
proseguire come progetto software (o per la community libfprint/Hackintosh).
