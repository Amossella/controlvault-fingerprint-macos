# Catturare enroll+verify su Linux (usbmon, in chiaro)

Obiettivo: vedere i comandi di load-template + identify (1:N) che mancano per il match.
Serve il driver grosa787 + firmware 4.12 (lo stesso con cui hai fatto enroll_final.pcap).

## 1. Prepara usbmon
    sudo modprobe usbmon
    lsusb | grep -i 0a5c:5834      # annota il BUS (es. "Bus 001")

## 2. Avvia la cattura (sostituisci 1 col numero di bus, SENZA zeri iniziali)
In un terminale, lascialo girare:
    sudo tcpdump -i usbmon1 -w ~/cv_verify.pcap
(se `usbmon1` non esiste: `ls /sys/kernel/debug/usb/usbmon/` per vedere i numeri)

## 3. In un ALTRO terminale: enroll + verify
    # cancella eventuali impronte vecchie di fprintd per partire pulito
    fprintd-delete $USER 2>/dev/null

    # ENROLL (appoggia il dito quando chiede, ~4-5 volte)
    fprintd-enroll

    # VERIFY (appoggia lo STESSO dito 1-2 volte)
    fprintd-verify

Va bene anche se il verify FALLISCE o dà errore: i comandi (load-template, capture,
identify) viaggiano comunque in chiaro e li leggo. Se fprintd dà "no devices available",
assicurati che il servizio sia attivo:  sudo systemctl restart fprintd  e riprova.

## 4. Ferma la cattura e passami il file
Ctrl+C sul tcpdump. Poi copia `~/cv_verify.pcap` sul Mac (es. /Volumes/HDD/ o ~/Downloads)
e scrivimi "ho il pcap verify".

## Cosa ne ricavo
- L'opcode/sequenza di LOAD TEMPLATE (blob 1388B -> handle nel chip)
- Il comando IDENTIFY 1:N in chiaro e il formato della sua risposta (quale template ha fatto match)
Poi lo cifro con la crypto gia' funzionante e testo il match col tuo dito sul lettore.

## Nota
Se `fprintd-enroll` non e' installato:  sudo apt install fprintd  (o il pacchetto della tua distro).
Se usi il lettore gia' su Linux con un tool custom del progetto invece di fprintd, va bene
uguale: basta che la cattura contenga un enroll seguito da un verify/identify.
