# La via affidabile: catturare il driver Linux reale (in chiaro)

## Perché
Il livello comandi è decodificato e verificato, ma il **trigger della scansione** (enroll/verify)
dipende dai parametri esatti dello strato cvif/libfprint, che non si indovinano dal device.
La soluzione definitiva: far girare il driver Dell **vero** su Linux (dove NON cifra i comandi)
e catturare il traffico USB. Si ottiene la sequenza enroll/verify completa, in chiaro, con tutti
i parametri reali. Poi la traduco 1:1 nel driver macOS `controlvault.py`.

È lo stesso metodo con cui abbiamo validato init e cv_open contro le catture Windows — ma stavolta
in chiaro, quindi utilizzabile al 100%.

## Cosa serve
Il tuo Dell Latitude 5580 e una chiavetta USB con un live di Ubuntu (24.04+). Nessuna
installazione permanente: si fa tutto dal live.

## Passi (sul Dell, da Ubuntu live)
1. Avvia Ubuntu live (prova Ubuntu, senza installare).
2. Apri un terminale e installa gli strumenti:
   ```bash
   sudo apt update && sudo apt install -y fprintd libpam-fprintd wireshark git
   sudo modprobe usbmon
   ```
3. Installa il driver Dell per questo chip (TOD):
   ```bash
   sudo apt install -y libfprint-2-tod1-broadcom
   # se non c'è nei repo, usa il progetto:
   # git clone https://github.com/grosa787/dell-controlvault2-fingerprint-linux
   # e segui il suo install.sh
   ```
4. Verifica che il lettore sia visto: `lsusb | grep 0a5c:5834` e `fprintd-list $USER`.
5. Avvia la cattura USB in un terminale (trova il bus con `lsusb` → di solito l'XHCI):
   ```bash
   sudo wireshark   # scegli l'interfaccia usbmonX del bus del lettore
   # filtro in Wireshark: usb.idVendor==0x0a5c && usb.idProduct==0x5834
   ```
   oppure da riga di comando:
   ```bash
   sudo tcpdump -i usbmon0 -w ~/enroll.pcap   # usbmon del bus giusto
   ```
6. In un altro terminale, registra un dito mentre catturi:
   ```bash
   fprintd-enroll
   ```
   Appoggia il dito quando richiesto, fino a enroll completato.
7. Poi cattura anche una verifica:
   ```bash
   fprintd-verify
   ```
8. Salva `enroll.pcap` (e verify) e copiali sul Mac in
   `~/Downloads/controlvault-pcap-captures/`.

## Cosa ne ricavo
Dalle catture in chiaro estraggo la sequenza esatta: enrollment_started, i cicli di
capture/update con i parametri reali, il commit, e il flusso di verify/identify — poi li
implemento in `controlvault.py` e li proviamo sul Mac.

## Alternativa
Se non vuoi usare Linux live, possiamo consolidare qui: la base (protocollo, mappa comandi,
libreria) è completa, e queste catture sono il tassello che mancava per finire il driver.
