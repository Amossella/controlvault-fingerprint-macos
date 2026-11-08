# Istruzioni: procurare il driver Windows (per il reverse della crittografia)

Scopo: ricostruire la sessione cifrata (0x23/0x24) che serve per salvare e verificare
l'impronta. L'algoritmo e' dentro il driver Windows bcmbipdll.dll. Lo disassemblo come ho
fatto col driver Linux.

## Nota firmware (tua domanda)
Va bene qualunque firmware. L'ALGORITMO di cifratura e' nella DLL e NON dipende dal firmware.
Le catture Windows vecchie restano valide per capire la struttura. Una cattura nuova (firmware
4.12) sarebbe solo una conferma in piu', non e' necessaria per iniziare.

## 1. ESSENZIALE — copia la DLL della crittografia
In Windows, apri **PowerShell** e lancia:
```powershell
Get-ChildItem C:\Windows\System32\bcmbip*.dll, `
  C:\Windows\System32\Drivers\cvusbdrv.sys, `
  "C:\Program Files\Broadcom\*" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length
```
Copia su una chiavetta exFAT TUTTI i file trovati, in particolare:
- `bcmbipdll.dll`   <- IL PIU' IMPORTANTE (contiene la crittografia)
- `bcmbipdefs.dll`  (se c'e')
- `cvusbdrv.sys`    (se c'e')
- qualsiasi altra `bcmbip*.dll` / `bcm*.dll` nella stessa cartella

Se PowerShell non trova nulla in System32, cerca anche qui:
```powershell
Get-ChildItem C:\ -Recurse -Filter bcmbipdll.dll -ErrorAction SilentlyContinue | Select FullName
Get-ChildItem C:\Windows\System32\DriverStore -Recurse -Filter bcmbip*.dll -ErrorAction SilentlyContinue | Select FullName
```
(La DLL spesso e' in C:\Windows\System32\DriverStore\FileRepository\...\ )

## 2. (FACOLTATIVO) cattura Windows nuova col firmware aggiornato
Solo se ti va, come conferma:
1. Installa USBPcap (https://desowin.org/usbpcap/) + Wireshark.
2. Avvia la cattura sul dispositivo del lettore impronte.
3. Fai in Windows Hello: rimozione + nuovo enroll (4 tocchi) e un paio di verify.
4. Salva enroll_win_new.pcapng e verify_win_new.pcapng.

## 3. Portami i file
Copia su chiavetta exFAT -> in macOS metti tutto in ~/Downloads/ e scrivimi "ho le dll".
File minimi che mi bastano per iniziare: **bcmbipdll.dll**.

## Cosa faro' con la DLL
La disassemblo e cerco: come costruisce il blocco 0x24 (RSA verso la chiave del chip), come
deriva la chiave di sessione, e con quale cifrario protegge i comandi (AES/HMAC). Se riesco a
ricostruirlo, implemento la sessione cifrata in controlvault.py -> commit e verify su macOS.

## Onesta'
E' crittografia da ricostruire da un binario chiuso: impegnativo, esito incerto. Ma e' il
metodo giusto e la fonte autorevole, lo stesso che ha funzionato per il driver Linux.
