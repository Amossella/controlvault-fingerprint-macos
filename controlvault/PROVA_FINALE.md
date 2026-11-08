# Prova finale (versione completa per live USB — da zero, in una sola sessione)

Importante: su Linux "live" tutto si perde al riavvio. Esegui TUTTO in una sessione e salva
i file risultato sulla CHIAVETTA exFAT (non nella home). Serve connessione internet.
Il firmware (aggiornato da Windows) resta nel chip anche dopo i riavvii: va bene.

Apri un Terminale e incolla i blocchi in ordine.

## 1. Strumenti + usbmon (da reinstallare ogni boot del live)
```bash
sudo apt update
sudo apt install -y git build-essential tcpdump usbutils fprintd libpam-fprintd
sudo modprobe usbmon
# rimuovi l'eventuale driver dei repo (quello SENZA il tuo 5834)
sudo apt remove -y libfprint-2-tod1-broadcom 2>/dev/null || true
```

## 2. Installa il driver PATCHATO (aggiunge il tuo 0a5c:5834)
```bash
cd ~
git clone https://github.com/grosa787/dell-controlvault2-fingerprint-linux
cd dell-controlvault2-fingerprint-linux
./build_from_upstream.sh     # IMPORTANTE: costruisce il driver patchato (scarica + patcha)
sudo ./install.sh
sudo udevadm control --reload && sudo udevadm trigger
sudo systemctl restart fprintd || sudo pkill -f fprintd
```
Nota: senza `build_from_upstream.sh` l'install dice "Patched driver not found. Build it first".

## 3. VERIFICA (non catturare se questo fallisce)
```bash
lsusb | grep 0a5c                 # deve apparire 0a5c:5834
fprintd-list "$USER"              # deve vedere "Broadcom Sensors", NON "No devices available"
```
Se dice "No devices available": il driver patchato non si e' agganciato. Salva comunque il log
(blocco 5) e scrivimi: non ha senso la cattura.

## 4. Cattura l'enroll (solo se il lettore e' visto)
Trova il bus del lettore:
```bash
lsusb | grep 0a5c                 # es. "Bus 001 Device 006" -> bus 001 -> usbmon1
```
In un terminale avvia la cattura (usa il numero di bus giusto, qui esempio bus 1):
```bash
sudo tcpdump -i usbmon1 -w /tmp/enroll_final.pcap
```
In un SECONDO terminale fai l'enroll (appoggia il dito piu' volte):
```bash
fprintd-enroll
```
Quando l'enroll finisce o fallisce, torna al primo terminale e premi Ctrl-C per fermare tcpdump.

## 5. Salva i file sulla CHIAVETTA exFAT
```bash
journalctl -u fprintd -b > /tmp/fprintd_final.log 2>/dev/null
# trova il punto di mount della chiavetta exFAT (di solito /media/<utente>/<NOME>)
ls /media/$USER/
# copia (sostituisci NOME_CHIAVETTA):
cp /tmp/enroll_final.pcap /tmp/fprintd_final.log /media/$USER/NOME_CHIAVETTA/
sync
```

## 6. In macOS
Copia enroll_final.pcap e fprintd_final.log in ~/Downloads/controlvault-pcap-captures/ ,
riapri la chat e scrivi "prova finale fatta".

---
Note:
- Se `git clone` o `apt` falliscono: manca internet nel live. Collega wifi/ethernet.
- Se `install.sh` chiede di scaricare da Canonical e fallisce: riprova, o incollami l'errore.
- Il firmware non va ritoccato: e' gia' aggiornato nel chip.
