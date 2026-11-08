# Come catturare i byte crypto con Frida (Windows) — automatico

Lo script frida_hook.js fa tutto da solo: hooka le funzioni crittografiche di
HostControlService.exe e scrive in un file cosa cifra, l'IV, cosa hasha, input/output.
A te basta lanciarlo e fare un enroll. Poi mi mandi il file.

## 1. Installa Frida (serve Python, che hai gia')
In PowerShell (anche normale):
```
pip install frida-tools
```
Se "pip" non va, prova:  `python -m pip install frida-tools`

## 2. Copia lo script su Windows
Metti `frida_hook.js` in una cartella comoda, es. C:\cv\  (copialo dalla chiavetta).

## 3. Lancia la cattura (PowerShell COME AMMINISTRATORE)
```
cd C:\cv
frida -n HostControlService.exe -l frida_hook.js -o crypto_log.txt
```
- Deve apparire una riga tipo "[+] hook: advapi32.dll!CryptHashData ..." per ogni hook,
  e poi "[*] Hook pronti. Ora fai un ENROLL...".
- Se dice che HostControlService.exe non e' in esecuzione: apri Impostazioni -> Account ->
  Opzioni di accesso -> Impronta, cosi' il servizio parte, poi rilancia il comando.
- Se da' errore di permessi: assicurati che PowerShell sia "come amministratore".

## 4. Fai l'enroll
Con Frida in esecuzione, vai in Windows Hello (Opzioni di accesso -> Impronta digitale),
RIMUOVI l'impronta e fai un NUOVO enroll (i 4 tocchi). Fai anche una verifica se riesci.

## 5. Ferma e mandami il file
Torna alla finestra Frida, premi Ctrl+C (o scrivi `exit` e Invio).
Il file `crypto_log.txt` contiene tutto. Copialo in ~/Downloads/ sul Mac e scrivimi
"ho il log crypto".

## Cosa ci faccio
Dal log leggo i valori ESATTI (cosa si hasha per la chiave di sessione, l'IV, il formato
del comando sicuro). Con quelli finisco l'implementazione in cvcrypto.py e proviamo
commit/verify sul tuo lettore su macOS. La chiave pubblica del chip ce l'ho gia'.

## Se Frida da' problemi
Alternative: `frida -f "C:\...\HostControlService.exe" -l frida_hook.js -o crypto_log.txt`
(lancia il processo da zero). Oppure dimmi l'errore esatto e ti aggiusto il comando.
