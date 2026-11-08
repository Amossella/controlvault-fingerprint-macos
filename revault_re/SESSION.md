# ControlVault BCM5880 — sessione ricostruita dal driver Dell

Fonte: `libfprint-2-tod-1-broadcom.so` (ELF x86-64, stripped) + catture USBPcap.
Scanner statico: `elfmap.py`. Client di prova: `../tools/cv.py`.

## Architettura (dal binario)

- **Trasporto = libusb puro.** La funzione a `~0x28980` fa, per OGNI comando:
  open device (VID:PID) → claim → `bulk_transfer` OUT → `interrupt_transfer` (notifica) →
  `bulk_transfer` IN → release/close. Nessuna chiamata crittografica nel trasporto.
  È esattamente il pattern già replicato in `cv.py`.
- **Crittografia lato host = minima.** Unica funzione crypto a `~0x2da61`:
  `PEM_read_RSA_PUBKEY` → `SHA256` → `RSA_verify`. Serve a **verificare il certificato
  del device** contro una chiave Dell incorporata. NON cifra i comandi.
  Nessuna AES/HMAC/ECDH lato host (nessun import, nessuna S-box nel binario).
- **Crittografia simmetrica = sul chip.** AES/HMAC/SuiteB/ECDH girano nel firmware,
  invocati via comandi `cvhSetUpSecureSession`, `GetCVSecureSessioncmd`,
  `cvhEncryptCmd`/`cvhDecryptCmd`, `cvhEncapsulateCmd`. Il tag `USH_AES_KEY_VALID`
  indica che la chiave di sessione vive nel chip.
- **Nonce dell'host = `rand()`.** Il builder dell'header (`~0xe9c0`) fa
  `GetSessionOfTheHandle` → `time()` → `srand()` → `rand()` → `malloc`.
  Quindi il campo variabile di 24 byte nel comando `0x23` è un nonce di transazione
  pseudo-casuale (time+rand), NON un valore crittografico.

## Envelope (confermato dalle catture)
```
offset 0  seq        (4 LE)
offset 4  total_len  (4 LE)
offset 8  cmd_word   (4 LE)  byte3: 0x00=request 0x01=response
offset 12 counter    (4 LE)  1=init, 2=comandi di sessione
offset 16 handle     (4 LE)  0 all'apertura; poi il puntatore heap del chip
offset 20 status     (4 LE)  0=OK nelle risposte; 0x0f=errore
offset 24..39        riservati (0)
offset 40 data_len   (4 LE)
offset 44 data[...]
```

## Sequenza di apertura sessione
1. `0x82` init — statico, nessun handle. (replay OK, già verificato su macOS)
2. `0x23` **cv_open**: handle_in=0, data = nonce host (24B, da `rand()`).
   Risposta 320B = certificato/chiave pubblica del device (i primi 256B STATICI) +
   materiale del device; l'envelope di risposta porta un **handle fresco** `0x1400xxxx`.
3. `0x24`: handle = quello nuovo, data 256B. Completa la sessione (lato chip).
4. Comandi impronta: `0x02`, `0x66`, `0x73` con lo stesso handle.

## Perché il replay dava status 0x0f
Non è un rifiuto crittografico (l'host non possiede chiavi simmetriche). Il payload
catturato del `0x02` contiene materiale legato alla sessione Windows (handle + nonce di
quella sessione) nei suoi dati, non solo nell'envelope. Sostituendo solo l'handle
dell'envelope, i DATI restavano quelli vecchi → il chip rifiuta (0x0f).
Soluzione: costruire ogni comando **da zero** con l'handle corrente e il nonce della
sessione aperta ora, come fa il builder `~0xe9c0`, invece di rigiocare i byte.

## CORREZIONE IMPORTANTE: catture Windows ≠ driver Linux
Analisi: né i 256B del `0x24` né i 36B del `0x02` delle catture sono (a) copiati dal
materiale del `cv_open`, (b) echeggiati dal chip, (c) prodotti dall'host (che NON ha
AES/HMAC/ECDH: nessun import OpenSSL simmetrico, nessuna S-box, nessuna AES-NI/PCLMULQDQ).
Conclusione: le catture vengono da `bcmbipdll` di **Windows**, che instaura una
**sessione CIFRATA** (i blob ad alta entropia). Il `.so` **Linux** che fa funzionare
enroll/verify NON ha crittografia → usa un percorso "plain" che il chip accetta senza la
sessione cifrata. Quindi **il blueprint da seguire è il `.so` Linux, non i pcap Windows**.
I pcap restano utili solo per envelope e handshake di apertura.

## Verifica sul device (macOS, oggi)
`cv_open` (0x23) inviato con un **nonce casuale generato dall'host** → `status=0`,
handle fresco, 320B di certificato. Due aperture → certificato IDENTICO (chiave pubblica
statica), handle diverso. Conferma: l'apertura è controllata dall'host, da zero, senza
crittografia. Il replay del `0x02` cifrato dà `0x0f` perché è traffico della sessione
cifrata Windows, non perché manchi una chiave all'host.

## Cosa manca per enroll/verify nativi su macOS
Tutto reverse engineering normale, senza rompere crittografia:
1. Disassemblare nel `.so` Linux i builder del percorso plain: `cv_enable_fingerprint`,
   `cv_identify_user`, `cv_fingerprint_create_feature_set/commit_enrollment`, e capire
   quali comandi manda (opcode + layout dei data block) DOPO `cv_open` — probabilmente
   SENZA il `0x24` cifrato.
2. Riprodurre quei comandi plain su libusb e testarli sul device (status atteso 0).
3. Reimplementare il flusso completo (trasporto già provato da `cv.py`).
4. Modulo PAM per `sudo`/CLI; login grafico = authorization plugin macOS (più difficile).

## PERCORSO PLAIN ricostruito dal .so Linux (2026-11-07)
Il `.so` esporta 329 funzioni con NOME e indirizzo (dynsym) → è un binario etichettato.

Prova decisiva "niente crittografia" nel driver Linux:
- `cvhEncryptCmd` (0x1ed10): solo `calloc`/`memcpy`/`Free` — NESSUN cifrario.
- `cvhSetUpSecureSession` (0x207a0): praticamente uno stub (solo `Free`).
- Unica crypto in tutto il binario: `RSA_verify` del certificato device (autenticazione, opzionale).

Catena di una API impronta (es. `cv_identify_user` @ 0x22380):
1. `is_valid_handle` → `GetCVInternalHandle`
2. `InitParam_List(index, size/type, &value, list)` ×N — costruisce i parametri TLV
3. `cvhManageCVAPICall(...)` — dispatcher universale
4. `cvhSaveReturnValues`

Argomenti osservati del dispatcher per identify:
`cvhManageCVAPICall(edi=4, esi=paramlist, edx=2, rcx=handle, r8=0, r9=flags; stack: push 0, push 0x35)`
→ `edx=2` = encapsulation LENVAL_PAIR; `0x35`(53) = codice comando candidato per identify.

`cvhManageCVAPICall` (0x1f890) fa: `ConstructBlob` → `cvhEncapsulateCmd` (wrap LENVAL;
chiama `cvhEncryptCmd` che però è solo copia) → `ProcessTransmitCmd` (→ trasporto libusb
0x28980) → `cvhDecapsulateCmd` (unwrap risposta). Nessuna cifratura sul percorso.

### Prossimo passo (una sessione di RE mirata)
Decodificare `ConstructBlob` (0xf070) + `cvhEncapsulateCmd` (0x1ee80) + `InitParam_List`
per emettere i byte esatti del comando identify, poi costruirlo con `cv.py` e testarlo sul
device (atteso status 0 + match on-chip al tocco del dito).

## FORMATO DECODIFICATO E VALIDATO (2026-11-07)
Encoder: `../tools/cvproto.py`. Validato: riproduce l'init `0x82` catturato BYTE-PER-BYTE,
e init+cv_open costruiti da zero danno `status 0` sul device.

- **Parametro** (`InitParam_List` @0xe0b0): `[encap_type:4 LE][len:4 LE][value:len]`.
  `encap_type`: 0=STRUC, 1=LENVAL_STRUC, 2=LENVAL_PAIR, 3=INOUT (solo header, nessun valore).
- **Blob dati** (`ConstructBlob` @0xf070): concatenazione dei parametri; `value` con
  **padding a multiplo di 4 byte**; i parametri type==3 contribuiscono solo l'header (8B).
- **Envelope** (confermato): `[seq:4][total_len:4][cmd_word:4][counter:4][handle:4]
  [status:4][16B zero][data_len:4][blob]`.
- **Prova**: init `0x82` = un parametro `(STRUC, len4, value=0x00000000)`.
- `is_valid_command_id` @0xe230: id validi 0–33 e 35–54; `0x35`(53) valido (identify).

### Ultimo passo verso identify live
Resta la mappatura command_id → `cmd_word` (fatta da `GetCommandIndex`/`cvhManageCVAPICall`)
e i parametri esatti di `cv_identify_user` (6 InitParam_List). Poi: `cvproto.envelope(cmd_word,
cvproto.blob([...]))` e test sul device col tocco del dito.

## IDENTIFY ricavato (2026-11-07)
`cv_identify_user` @0x22380 → `cvhManageCVAPICall(num_param_in=4, paramlist, encap=2,
handle, 0, flags; push 0, push 0x35)`.
- **Command code = 0x35 (53)** (arg8), preso a 16 bit. `is_valid_command_id` lo conferma.
- 4 parametri di input (slot contigui a rsp+112…136) + 2 di output (rsp+64/72):
  1. `(STRUC, len=4, value=uint32)` — flag/tipo (da rsp+60)
  2. `(LENVAL_PAIR, buffer)` — input var. (len e ptr dagli argomenti del chiamante)
  3. `(LENVAL_PAIR, buffer)` — input var. (len=ebp, ptr dagli argomenti)
  4. `(INOUT, header-only)` — buffer di output riempito dal chip
- `GetCommandIndex` @0xf990: il cmd_word sul filo è ricavato da una tabella relativa
  all'header del blob (campi a offset 4 e 10), non da una costante statica.

### Realtà: identify non è un singolo comando
I VALORI dei parametri 2–3 arrivano dagli argomenti di `cv_identify_user`, passati dallo
strato libfprint (`cv_do_fingerprint_identify`). E identify confronta contro template GIÀ
registrati. Quindi una verifica reale richiede la sequenza completa:
`cv_open → cv_enable_fingerprint → (autorizzazione sessione) → enroll di un dito → identify`,
più i valori dei parametri dallo strato libfprint. È l'implementazione del driver vero e
proprio, non un singolo comando di test. La MACCHINA di costruzione comandi però è pronta e
validata (`cvproto.py`): init e cv_open costruiti da zero funzionano sul device.

## ENROLL: command code ricavati + probe (2026-11-07)
Dispatch letti dal driver (arg8=command code, arg1=num param input, arg3=encap):
- `cv_enable_fingerprint`  = code **0x41 (65)**, encap 0, 2 param STRUC:
  P0 = `GetCVInternalHandle(handle)` (contabilità host), P1 = flag enable (0/1).
- `cv_cmd_enrollment_started` = code **0x8a (138)**, encap 0, 1 param STRUC.
- `cv_identify_user` = code 0x35, encap 2 (vedi sopra).

Probe sul device (enable, code 0x41): l'envelope fa round-trip (byte3 req0→resp1).
status=0 per byte2 pari (0x40/0x42/0x44/0x46), status=15(0x0f) per byte2 dispari. dlen=0.
AMBIGUO: più byte2 danno status 0 e non c'è effetto osservabile → non confermo l'abilitazione.

### Il pezzo mancante: tabella descrittori comandi
`GetCommandIndex` @0xf990 ricava il `cmd_word` sul filo da un descrittore per-comando
(lookup a `header[4]` + 0/16 secondo un bit di `header[10]`), impostato da cvhManageCVAPICall
da una mappa code→descrittore. Trovare quella tabella statica darebbe il `cmd_word` esatto
di OGNI comando in modo deterministico (es. code 0x82→byte2 0x40, code 0x23→byte2 0x41).
È l'artefatto chiave per smettere di sondare a tentativi.

### Valutazione onesta
Un enroll funzionante richiede: tabella descrittori (cmd_word esatti) + semantica di
`GetCVInternalHandle`/tabella sessioni host + eventuale autorizzazione sessione +
i valori dei parametri dallo strato libfprint. È il porting del driver host Dell: settimane.
Il probing black-box non basta a fissarli. Ciò che è SOLIDO e verificato: blocco USB risolto,
protocollo/envelope/formato comandi decodificati, encoder validato (init+cv_open da zero = status 0).

## La "tabella" non esiste: cmd_word cablati per comando (2026-11-07)
`GetCVPublicKeyCmd` @0xeac0 (il comando di cv_open) costruisce il cmd_word così:
`eax = [rdx+8]; eax &= 0xffbe0000; eax |= 0x00410023; [rdx+8] = eax`.
→ `0x00410023` è una COSTANTE cablata nel builder di quel comando (OR su template mascherato);
scrive anche data_len e seq nella stessa struttura (envelope offset 8 = cmd_word, 40 = data_len).
Ogni comando dell'handshake ha il proprio builder con il cmd_word a mano.
I comandi generici (enable 0x41 / identify 0x35 / enroll) NON hanno un builder dedicato:
il cmd_word lo calcola `cvhManageCVAPICall` da (opcode + categoria + encap), dentro la
command-state machine (getCommandIndex/appendCommandIndex/processCommand).
Non c'è un array statico opcode→cmd_word da leggere (cercato a stride 1-16: nessun match).

## CONCLUSIONE DEFINITIVA
Per completare enroll/identify serve tracciare/riscrivere la logica generica del cmd_word in
cvhManageCVAPICall + la tabella sessioni host (GetCVInternalHandle/AddNewSession) + eventuale
autorizzazione + i parametri dallo strato libfprint. Non è un singolo dato mancante: è il
driver host. Il probing a tentativi non lo fissa. Punto di arrivo onesto di oggi:
- RISOLTO e verificato: blocco USB (fix config 0), protocollo, envelope, formato comandi,
  encoder validato (init+cv_open da zero = status 0 sul device), command code dei verbi.
- DA FARE (progetto driver, settimane): logica generica cmd_word, stato sessione host,
  integrazione libfprint, PAM. Base di partenza completa: questo documento + i tool.
