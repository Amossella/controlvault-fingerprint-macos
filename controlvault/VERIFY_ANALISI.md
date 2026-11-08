# Analisi VERIFY/IDENTIFY (da verify_log.txt, Frida Windows, 2026-11-08)

## Cosa abbiamo scoperto
Il verify di Windows Hello usa l'opcode **0x73** (cat 0x43 cifrato) come MATCH, NON 0x35.
Flusso catturato (sessioni cifrate separate, come enroll):
- Sessione A: open 0x02 → capture 0x66 (scansiona il dito nel buffer del chip)
- Sessione B: open 0x02 → **0x73 (match)** → risposta `result=1` + ID 20B del template che ha fatto match

### Comando 0x73 (72B data)
    00000000 04000000 <ihandle>          # handle sessione
    00000000 04000000 48010000           # param 0x148 (328)
    00000000 04000000 e2530000           # param 0x53e2 (21474)
    00000000 04000000 00000000           # 0
    02000000 08000000 4cc15d00 f199da00  # idx2, 8B = handle(s) template (0x5dc14c, 0xda99f1)
    03000000 14000000                    # idx3, len=0x14 (slot risultato 20B)

### Risposta 0x73 (52B data)
    04000000 01000000                    # result = 1  (MATCH TROVATO)
    00000000 04000000 4cc15d00           # template handle = 0x5dc14c
    03000000 14000000 <20B>              # ID del template/credenziale che ha fatto match

## Il blocco
I parametri `0x148`, `0x53e2`, `0x5dc14c`, `0xda99f1` sono **handle di oggetti template**
nella memoria del chip, creati quando Windows Hello CARICA i template all'avvio del servizio
biometrico (comandi di "load template" dal blob). La cattura Frida è partita DOPO quel caricamento,
quindi non li abbiamo. Provato sul device (capture→0x73 con quei valori): status 0x85 = oggetto
non pronto/non trovato — confermato che servono i comandi di load template.

## Cosa manca (da catturare)
I comandi che trasformano un template BLOB (come il 1388B del nostro commit) in un handle
caricato nel chip. Due strade:
1. **Linux fprintd** (consigliata): `fprintd-enroll` + `fprintd-verify` con usbmon. Flusso
   completo IN CHIARO (load template + capture + identify 1:N), modello self-contained vicino
   a quello che costruiremo per il PAM macOS. La crypto su Linux e' stubbata ma i COMANDI
   viaggiano in chiaro e li leggiamo con tools/usbmon.py.
2. **Windows cold**: riavvia il servizio biometrico (WbioSrvc) con Frida agganciato e cattura
   il primo verify → include il load dei template.

## Stato
Enroll+commit: RISOLTO. Verify: opcode e formato match noti (0x73), manca il load-template.
