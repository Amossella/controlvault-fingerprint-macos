# Catturare il comando VERIFY/IDENTIFY (per completare l'autenticazione)

L'enroll è risolto. Per la verify serve UNA cattura reale del comando identify: indovinare
dà sempre status 0x60 e non converge (stessa ragione per cui l'enroll l'abbiamo craccato
con byte reali, non a tentativi). Due strade — la Frida su Windows è la migliore (dà anche
il formato della RISPOSTA, che serve per il match).

## Opzione A — Windows + Frida (consigliata, stesso setup dell'enroll)
1. Su Windows, PowerShell COME AMMINISTRATORE in `C:\cv`.
2. Avvia un VERIFY di Windows Hello: Impostazioni → Account → Opzioni di accesso →
   Impronta digitale → "Configura"/riconoscimento, OPPURE blocca lo schermo (Win+L) e
   sblocca con l'impronta. (Il verify gira nel servizio biometrico, svchost WbioSrvc.)
3. Trova il PID che carica bipdll durante il verify:
       tasklist /m bipdll.dll
   (di solito lo stesso svchost.exe del servizio biometrico).
4. Aggancia Frida PRIMA di appoggiare il dito:
       frida -p <PID> -l frida_hook.js -o verify_log.txt
   Attendi "[*] Hook pronti", poi appoggia il dito per il riconoscimento. Ctrl+C alla fine.
5. Copia `verify_log.txt` sul Mac (es. in ~/Downloads o /Volumes/HDD/cv/) e scrivimi
   "ho il log verify". Mi bastano i blocchi CryptEncrypt PLAINTEXT/CIPHERTEXT (comando) e
   CryptDecrypt IN/OUT (risposta) attorno al riconoscimento.

## Opzione B — Linux + usbmon (più veloce, solo struttura comando)
Se preferisci Linux (driver grosa787 + firmware 4.12), cattura un verify in CHIARO:
1. Avvia la cattura usbmon sul bus del lettore (come per enroll_final.pcap).
2. Lancia:  fprintd-verify
   appoggia il dito; anche se il match fallisce (richiede la sessione cifrata), il COMANDO
   identify viaggia in chiaro e lo leggo con tools/usbmon.py.
3. Salva il pcap (es. verify.pcap) e passamelo.

## Cosa ne ricavo
L'opcode reale (0x35 o altro), la categoria, il layout dati (usa il risultato di capture?
che parametri di "identify type"?) e il formato della risposta (quale template/utente ha
fatto match). Poi lo cifro con la crypto già funzionante e lo testo subito col tuo dito.
