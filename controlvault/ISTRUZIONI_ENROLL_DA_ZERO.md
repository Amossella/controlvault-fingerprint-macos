# Catturare un ENROLL DA ZERO su Windows (il tassello finale)

## Perché serve
Abbiamo verificato tutto il resto:
- enroll + commit su macOS → funziona, ma produce solo il **blob** del template;
- il blob NON diventa un oggetto **residente** matchabile (identify vuoto → 0x47 = nessun oggetto);
- il log Windows che avevamo era una **ri-registrazione** di un dito già presente, quindi il
  commit#2 restituiva l'handle di un oggetto **già esistente** (0x5dc14c). Non contiene il
  comando che CREA l'oggetto residente la prima volta.

Serve quindi catturare un enroll **di un dito mai registrato prima**: lì comparirà il comando
che trasforma il blob in oggetto residente con handle (probabilmente `cv_create_object` op=0x09
o `cv_set_object` op=0x0b, che nel binario esistono ma non comparivano nella ri-registrazione).

## Passi
1. **Windows → Impostazioni → Account → Opzioni di accesso → Impronta digitale → Rimuovi**
   TUTTE le impronte registrate. (Così il prossimo enroll è "da zero".)

2. PowerShell **come amministratore** in `C:\cv`. Trova il processo biometrico:
       tasklist /m bipdll.dll

3. Aggancia Frida e avvia il log:
       frida -p <PID> -l frida_hook.js -o enroll0_log.txt
   Aspetta `[*] Hook pronti`.

4. Torna in Impostazioni → Impronta digitale → **Aggiungi/Configura**: registra UN dito
   (i soliti ~4-6 tocchi). Appena finito, se te lo chiede fai anche **un verify/sblocco**
   con lo stesso dito (Win+L → sblocca) per avere pure il match.

5. `Ctrl+C`, copia `enroll0_log.txt` sul Mac (`/Volumes/HDD/cv/` o `~/Downloads`) e scrivimi
   **"ho l'enroll0"**.

## Cosa cerco
- Un comando (opcode 0x09 create_object, 0x0b set_object, o simile) che invia il **blob** del
  template al chip e ne riceve l'**handle** → è il "load" che replicherò su macOS col mio blob.
- Oppure, se l'enroll da zero fa restituire l'handle direttamente dal commit, la differenza
  esatta rispetto al mio flusso.

Con quello, l'ultimo pezzo (rendere residente il template registrato su macOS) è fatto.

## Nota
Se non vuoi cancellare le impronte Windows: registrane una su un **dito nuovo** mai usato
prima (va bene uguale, basta che quel dito non sia già registrato). L'importante è che sia
una registrazione nuova, non un aggiornamento di un dito esistente.
