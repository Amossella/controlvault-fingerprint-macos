# Catturare il comando di CANCELLAZIONE dal chip (Windows)

Per implementare la rimozione reale di un'impronta dalla NVRAM del lettore
(`cv_delete_object`) serve, come per tutti gli altri comandi, una **cattura
Windows** del comando vero: non basta l'opcode (probabile `0x0a`, tra
`cv_create_object=0x09` e `cv_set_object=0x0b`), serve anche il **layout esatto
dei parametri**. Indovinarlo significherebbe mandare un comando che *scrive* sul
chip — rischioso per i template buoni. Quindi lo catturiamo.

## Cosa serve
- Il portatile avviato in **Windows** con Windows Hello funzionante (impronta
  registrata e riconosciuta).
- **Python + Frida** su Windows (`pip install frida-tools`), come già usato per
  l'enroll. Lo script di hook è `frida_hook.js` (questa stessa cartella).

## Procedura
1. Copia `frida_hook.js` su Windows.
2. Individua il processo del servizio biometrico (lo stesso dell'enroll). In genere:
   - `WinBioService` dentro un `svchost.exe`, **oppure** il processo di ControlVault
     Dell (`ControlVault`/`BtmService`). Se non sei sicuro, usa lo stesso processo
     che avevi hookato per l'enroll (vedi `ISTRUZIONI_FRIDA.md`).
3. Avvia l'hook, reindirizzando l'output in un file:
   ```
   frida -p <PID> -l frida_hook.js  > delete_log.txt 2>&1
   ```
   (oppure `frida -n <processo> -l frida_hook.js`)
4. Quando lo script stampa "hook pronti", vai in **Impostazioni Windows →
   Account → Opzioni di accesso → Impronta digitale** e premi **Rimuovi** su
   un'impronta. Conferma.
5. Ferma Frida (Ctrl+C). Avrai `delete_log.txt`.

## Cosa mi serve ricevere
- Il file **`delete_log.txt`** completo.
- Se possibile, nota **quale handle/impronta** hai rimosso (così riconosciamo il
  valore nel log).

## Cosa farò con la cattura
Dal log ricavo:
- il **cmd_word** del delete (opcode + categoria + direzione),
- il **blob dei parametri** (quasi certamente contiene l'handle a 4 byte del
  template, come in verify/commit),
- la risposta/stato di conferma.

Poi implemento `delete_object(handle)` in `secure.py` e collego il pulsante
**Rimuovi** di FP Manager alla cancellazione reale (con test prima su un dito
"usa e getta", per non rischiare quelli buoni).

> Nota: finché non c'è questa cattura, "Rimuovi" in FP Manager scollega soltanto
> l'impronta (non viene più usata per sudo/sblocco); il template resta nel chip.
> Il chip ha comunque spazio per diversi template, quindi non è urgente.
