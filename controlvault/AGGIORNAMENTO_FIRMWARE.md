# Aggiornamento firmware ControlVault2 + ri-cattura

Obiettivo: portare il firmware del lettore da quello di fabbrica (ottobre 2016) a 4.12.x,
che il driver open-source richiede per l'enroll. Poi rifare la cattura su Linux.

## Stato attuale del tuo chip (dalla cattura)
- USH_CHIPID: 05810211  (Broadcom BCM5880 / ControlVault2)
- Firmware build: Oct 21 2016  (VECCHIO — causa del fallimento enroll)
- CV_VER: 01000235 · REL_UPGRADE_VER: 00045013

## Parte 1 — Aggiorna il firmware (in Windows)
1. Collega l'alimentatore (NON scollegarlo durante l'update). Batteria carica.
2. Vai su https://www.dell.com/support , inserisci il **service tag** del Dell.
3. Sezione Driver → cerca **"Dell ControlVault2 Driver and Firmware"**.
   Scarica la più recente compatibile col 5580:
   - A25  4.12.11.15  (file ...NX3HH...A25...EXE), oppure
   - A21  4.12.5.8   (file ...43NG7...A21...EXE, elenca esplicitamente il 5580).
4. Esegui l'EXE. Lascia completare l'aggiornamento FIRMWARE (non solo il driver).
   NON sospendere/spegnere durante l'operazione. Riavvia a fine installazione.
5. (Facoltativo, conferma) In Gestione dispositivi o nell'app Dell, verifica che la
   versione ControlVault sia ora 4.12.x.

Nota: dopo l'update non si può tornare a versioni molto vecchie. È un update ufficiale
Dell: non rompe Windows e il rischio di brick è basso se non interrompi l'operazione.

## Parte 2 — Rifai la cattura (in Linux Mint)
Stessa procedura di prima:
```bash
sudo apt update && sudo apt install -y fprintd libpam-fprintd wireshark git
sudo modprobe usbmon
# installa il driver TOD broadcom (pacchetto o progetto grosa787)
lsusb | grep 0a5c:5834            # conferma il device
# avvia cattura usbmon del bus giusto (Wireshark o tcpdump), filtro 0a5c:5834
fprintd-enroll                    # appoggia il dito quando richiesto
fprintd-verify
# salva: il nuovo fprintd log + enroll.pcap su chiavetta exFAT
```
Cattura ANCHE il log del demone:
```bash
journalctl -u fprintd -b > fprintd3.log
```

## Parte 3 — Portami i file (in macOS)
Copia in ~/Downloads/controlvault-pcap-captures/ :
- il nuovo pcap (es. enroll3.pcap)
- fprintd3.log
Poi riapri questa chat e scrivimi "firmware aggiornato, ho i file".

## Cosa succede dopo
- Se nel nuovo log NON c'è più "could not determine chip type" e l'enroll riesce:
  traduco la sequenza enroll/verify (in chiaro) in controlvault.py → impronta su macOS.
- Se fallisce ancora: lo vedremo dal log e avremo escluso la strada firmware.
