# Catturare LOAD + ENUMERATE template (Windows Frida) — metodo "cold boot"

Obiettivo: catturare i comandi che il servizio biometrico manda quando CARICA i template
nel chip e li ELENCA (enumerate objects). Servono per trovare l'handle del template che
registreremo su macOS. Questi comandi partono UNA SOLA VOLTA, al primo uso dell'impronta
dopo l'avvio — se Frida si aggancia dopo, vede solo il verify (handle già in cache).

La chiave: **nessun uso dell'impronta tra il riavvio e l'aggancio di Frida.**

## Passi

1. **Riavvia Windows.**

2. Alla schermata di login **accedi con PIN o password** — NON con l'impronta.
   (Così il chip non ha ancora caricato i template.)

3. Sul desktop apri **PowerShell COME AMMINISTRATORE** in `C:\cv` e trova il processo:
       tasklist /m bipdll.dll
   - Se compare un `svchost.exe` con un PID → vai al passo 4.
   - Se NON compare nulla, il driver non è ancora caricato: passa al passo 4 e aggancia
     per nome appena serve, oppure aspetta qualche secondo e rifai `tasklist /m bipdll.dll`.

4. Aggancia Frida e AVVIA il log (sostituisci `<PID>`):
       frida -p <PID> -l frida_hook.js -o load_log.txt
   Aspetta la riga **`[*] Hook pronti`**.

5. **SOLO ORA** usa l'impronta per la **prima volta** dal riavvio:
       Win+L  →  sblocca col dito registrato
   Questo primo sblocco innesca **load + enumerate** dei template.
   (Se vuoi, fai anche un secondo sblocco per avere pure il verify nello stesso log.)

6. `Ctrl+C` per fermare Frida. Copia `load_log.txt` sul Mac
   (`/Volumes/HDD/cv/` o `~/Downloads`) e scrivimi **"ho il load"**.

## Cosa cerco nel log
- Un comando la cui RISPOSTA elenca più **handle** di oggetti template → *enumerate objects*
- Eventuali comandi che trasferiscono un **BLOB** template nel chip → *load template*
- Conferma che l'handle corrisponde a `0x5dc14c` già visto nel verify.

## Se non funziona
- Se Frida non riesce ad agganciarsi prima del primo sblocco, oppure il log contiene di nuovo
  solo il verify (opcode 0x02 / 0x66 / 0x73 e basta): vuol dire che il caricamento avviene
  già all'avvio del servizio, prima del login. In quel caso scrivimi **"solo verify di nuovo"**
  e passo al **piano B**: PAM funzionante subito col match attuale, enrollment nativo come
  passo successivo.
