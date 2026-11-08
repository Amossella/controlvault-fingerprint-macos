# ENROLL CIFRATO RISOLTO — commit 0x8d superato (2026-11-08)

Il blocco storico del progetto (commit `0x6e` rifiutato con `0x8d`, "bug noto e irrisolto"
della community grosa787) È RISOLTO riproducendo la **sessione cifrata di Windows**.
Enroll COMPLETO con `COMMIT status=0x0` + template da 1388 byte salvato nel chip, su macOS.

## La chiave mancante: contatore di sequenza nell'HMAC
`cvcrypto.build_secure_envelope` calcola l'HMAC su:

    HMAC-SHA1( hmac_key , header(44) || data || seq_u32_LE )

dove `seq` è un contatore di sequenza della sessione sicura:
- `open` (0x02) usa SEMPRE seq = 0
- ogni operazione successiva (capture/update/commit) incrementa: 1, 2, 3, ...

Prima usavo zero-padding per allineare `data` a multiplo di 8 → per `open` (data=36, non
multiplo di 8) coincideva per caso con seq=0 e funzionava; per `capture` serviva seq=1 →
HMAC sbagliato → il chip rifiutava con `0x0f`. Verificato byte-per-byte contro il log Frida:
con `seq=1` il ciphertext riproduce ESATTAMENTE quello catturato da Windows.

Chiavi/formato (già in cvcrypto.py, verificati):
- AES-128-CBC key = SHA1(device_nonce[20] || host_nonce[20])[:16]
- HMAC key        = SHA1(b"CV secure session blob\x00")
- envelope: header 44B (IV a offset 24, data_len a offset 40) + ciphertext
- plaintext cifrato = data || HMAC(20) || zero-pad a 16 || PKCS7(16)
- RISPOSTA: status in CHIARO nell'header (offset 20), data_len a offset 40,
  IV risposta a offset 24, payload decifrato = data(data_len) || HMAC

## Sequenza enroll che funziona (secure.py SecureSession.enroll)
1. reset()  — in chiaro: discard 0x6d + capture-wait 0x68 (sblocca stato armato residuo)
2. open 0x02 (seq=0) → ihandle
3. per ogni tocco (Windows = 4):
   - capture 0x66 (36B) → status 0 + R (20B). MAI due capture di fila (→ 0x85).
   - attendi interrupt EP 0x85 = `03....` (dito giù)
   - update 0x6c (48B, contiene R) → status 0 + feat 52B; il template-ref dello stadio
     è feat[20:40]
4. dopo 4 stadi: commit 0x6e (96B) con l'ULTIMO template-ref + TAIL metadati "BroadcomWBF":
   `02000000 08000000 00000400 04000000 02000000 15000000 0101ff00 00000d00
    0c "BroadcomWBF" 00000000 03000000 00080000`
   → **COMMIT status=0x0** + template cifrato ~1388B.

Status osservati: capture 0x85 = armato/in attesa (non ri-catturare); update 0x8c = enroll
già completo (committa, non fare altri update); commit 0x0 = OK (era 0x8d col template azzerato).

## Stato device
Lo stato enroll è GLOBALE nel chip: se una sessione lascia una capture armata senza update,
la successiva dà 0x85. `reset()` (discard+capwait in chiaro) lo sblocca.

## Prossimi passi
- VERIFY / cv_identify (0x35) nella sessione cifrata: match on-chip contro il template.
  Non passa dal commit, quindi è l'altra metà per l'autenticazione.
- Integrazione PAM per sudo/login su macOS.
