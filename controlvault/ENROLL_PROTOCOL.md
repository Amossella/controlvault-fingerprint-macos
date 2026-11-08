# Protocollo enroll REALE (in chiaro, da cattura Linux, firmware 4.12)

Fonte: ~/usbcfg/linux_capture/enroll_final.pcap (driver patchato grosa787 + firmware 4.12.x).
Decodifica completa: ~/usbcfg/linux_capture/enroll_decoded_full.txt (parser tools/usbmon.py).

Envelope sul filo (confermato): [seq:4][total:4][cmd_word:4][counter:4][handle:4][status:4]
[16B zero][data_len:4][data]. cmd_word byte3: 0x04=request, 0x05=response. byte0=opcode,
byte2=categoria (0x40 generale, 0x42 per capture/scan). status a offset 20.

## Sequenza (quella che funziona FINO al commit)
1. 0x39 (x3)  info/capabilities chip  -> risposta 804 byte
2. 0x02       cv_open (myAppID+myUserID, data 52B) -> handle 0x14019b8c
3. 0x66 (cat 0x42) capture_start
4. interrupt 0x85 = 0300000000000000  => DITO rilevato
5. 0x8a       enrollment_started
6. ciclo per ogni tocco:
   0x66 capture_start -> dito 0x03 -> 0x6c update_enrollment (status 0, 52B feature set)
   (questi sono gli "enroll-stage-passed": la SCANSIONE FUNZIONA)
7. ultimo update 0x6c -> status 0x59 ("enrollment data ready")
8. 0x6e commit_enrollment (data 64B) -> **status 0x8d (141) = FALLISCE**
9. 0x6d discard, 0x04 cleanup

## Mappa opcode (dal traffico reale)
- 0x39 chip info          - 0x02 cv_open            - 0x66 capture_start (cat 0x42)
- 0x2f scan-read post dito - 0x68 capture wait/poll  - 0x04 close/cleanup
- 0x8a enrollment_started  - 0x6c update_enrollment  - 0x6e commit_enrollment (FALLISCE 0x8d)
- 0x6d discard_enrollment

## Dove si rompe
Tutto funziona — scansione del dito, stadi, feature set da 52B — fino al COMMIT (0x6e),
che il chip rifiuta con 0x8d (141). E' un BUG NOTO e IRRISOLTO (grosa787 issue #2/#15):
accade anche col driver ufficiale su Linux. Non e' il nostro codice.

## Implicazione per macOS
Un driver macOS puo' riprodurre tutta questa sequenza (scan + stadi funzionerebbero),
ma il commit fallirebbe 0x8d come su Linux: e' un rifiuto a livello di chip, non di driver.
Quindi un enroll COMPLETO non e' ottenibile finche' il commit 0x8d non e' risolto a monte.

## Pista alternativa (promettente): verify contro template registrato su Windows
Il match e' on-chip. Se registri il dito su WINDOWS (dove l'enroll si completa) il template
resta nel chip. Allora su macOS servirebbe solo la VERIFY (cv_identify), che NON passa dal
commit e quindi NON incontra il bug 0x8d. Da verificare, ma aggira il blocco dell'enroll.

## CAUSA VERA del commit 0x8d (confronto Windows vs Linux, 2026-11-08)
Utente conferma: su Windows l'enroll si completa in 4 tocchi (come Linux). Quindi NON e'
un problema di numero di stadi. Confronto delle sequenze:
- WINDOWS enroll (02-enroll.pcapng): OGNI operazione e' avvolta in SESSIONE CIFRATA:
  0x23 (GetCVPublicKey) + 0x24 (secure session, 256B blocco RSA) + 0x02, poi l'operazione.
  Commit 0x6e = 96 byte, dentro la sessione cifrata. Presente anche 0x73 (create template, 68B).
- LINUX enroll (enroll_final.pcap): nessun 0x23/0x24 (in chiaro). Commit 0x6e = 64 byte,
  col campo template da 20B AZZERATO -> chip risponde 0x8d.
ROOT CAUSE: il chip accetta in CHIARO la scansione (capture/update) ma PRETENDE la sessione
cifrata/autenticata per le operazioni sensibili: COMMIT (salvare template) e VERIFY (match).
Il driver Linux open DISABILITA la sessione cifrata (cvhSetUpSecureSession stub, cvhEncryptCmd
= memcpy), quindi scan funziona ma commit/verify no. Windows fa la cifratura reale -> funziona.
Questo spiega tutto (4 tocchi ok, commit 0x8d, ok su Windows, bug community irrisolto).

## Implicazione finale
Enroll-save e verify (su Linux O macOS) richiedono di RICOSTRUIRE la sessione cifrata Windows:
RSA verso la pubkey del chip (0x24), derivazione chiave di sessione, cifratura comandi (AES/HMAC).
E' il muro di crittografia chiusa (dentro bcmbipdll di Windows). Ora pero' e' scopo preciso:
serve SOLO per commit e verify, e abbiamo le catture Windows 0x23/0x24 come base.
