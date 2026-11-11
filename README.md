# ControlVault Fingerprint for macOS

Native fingerprint **enrollment, verification and authentication** on macOS for the
**Dell ControlVault2 / Broadcom BCM5880** reader (USB `0a5c:5834`), reverse-engineered
from the Windows driver. Enroll your fingers *directly on macOS* — no Windows needed —
and use them for **`sudo`** and **screen unlock**.

Developed and tested on a Dell Latitude 5580 Hackintosh running macOS Sequoia (OpenCore).

> ⚠️ **Research / hobbyist project.** It talks to the sensor over raw USB and reproduces
> the vendor's encrypted secure session. No warranty. Use at your own risk, and keep a
> root shell / password fallback open while testing PAM.

---

## What works

| Feature | Mechanism | Status |
|---|---|---|
| **Enroll a finger on macOS** | encrypted secure session, on-chip template | ✅ |
| **Verify / match** | on-chip match (`result=1` / `0`) | ✅ |
| **`sudo` with fingerprint** | PAM module `pam_cvfp.so` | ✅ |
| **Screen unlock** | user-space daemon + Accessibility autofill | ✅ |
| **GUI manager** (add/rename/remove/verify) | `fpmanager.py`, Touch-ID-style | ✅ |
| **System Settings "enter password" prompts** | Secure-Input-gated CGEvent auto-type | ✅ *see note* |

### How System Settings prompts work (auto-type)

The admin "*enter your password to allow…*" dialogs in **System Settings** (and lock
toggles) are drawn by macOS through **`LocalAuthenticationRemoteService`** — an
out-of-process secure view that is **invisible to Accessibility by design** (you cannot
read or set the field value), the same wall that protects Touch ID / the Secure Enclave.
PAM is not involved either.

They can still be filled by **typing**: synthetic `CGEvent` keystrokes posted at the HID
tap **pass through Secure Input** and reach the secure field (verified on this machine —
all characters appear as dots). So the daemon detects a focused password field via
**`IsSecureEventInputEnabled()`**, and on a fingerprint match types the stored password
+ Return. The password is typed **only** when (a) a fingerprint matched and (b) Secure
Input is active — i.e. only when a real password field has focus, never scattered into
ordinary text fields. This also covers `sudo`/password prompts in Terminal and other
apps' secure fields.

This hardware still **cannot emulate Apple Touch ID**: biometric matching for Touch ID
happens inside the Secure Enclave with keys fused in Apple silicon, unreachable by any
third-party reader or kext. What we do instead is match on the reader's own chip and then
*type* the password, which is why it works where Touch ID emulation cannot.

---

## Architecture

Only **one process ever opens the reader**: the arbiter. Everything else is a client.

```
 sudo ─ pam_cvfp.so ─ fpauth.py ─┐
 screen lock / password prompts ─ fpunlock.py ─┤   Unix socket (0600)     ┌──────────────┐
 FP Manager (GUI) ───────────────┼── controlvault/arbiter.sock ──▶ │ fparbiterd.py │──▶ USB reader
 fpenroll / fpverify / fpdelete ─┘        JSON lines              └──────────────┘
```

- **`fparbiterd.py` (arbiter)** — LaunchAgent that owns the ControlVault. It serialises
  `verify` / `enroll` / `remove` / `rename` / `list` / `reset` behind one lock, so two
  secure sessions can never overlap (the cause of the "handshake 0B / reader not ready"
  lock-ups when several tools opened the reader themselves). It keeps the encrypted
  session **open between verifications** (5 minutes idle), so repeated matches skip the
  ~3 s handshake, and it transparently reopens a session the chip has dropped.
- **`fpunlock.py` (daemon)** — watches for the lock screen and focused password fields,
  asks the arbiter for a match, and only then types the stored password.
- **`fpauth.py`** — one-shot helper run by the PAM module during `sudo`.
- **`cvfp_config.py`** — the single place for paths, timeouts and thresholds. All paths
  are derived from the checkout location; nothing is tied to a user name.

If the arbiter is not running, fingerprint auth is simply unavailable and everything
falls back to the password — clients never touch the reader directly.

---

## How it works (protocol)

The BCM5880 speaks a 44-byte envelope over bulk EP `0x01`/`0x81` with an interrupt channel
on `0x85`. Secure operations run inside an **encrypted session**:

- **Handshake**: RSA-2048 PKCS#1 v1.5 + SHA-1 to exchange nonces.
- **AES-128-CBC** payload encryption; key = `SHA1(device_nonce || host_nonce)[:16]`.
- **HMAC-SHA1** integrity with a per-session **monotonic sequence counter**
  (`HMAC(key, header || data || seq_u32_LE)`) — the missing piece that made `commit`
  finally succeed where the Linux/plaintext community attempts failed with `0x8d`.
- Enroll: `open` → 4×(`capture 0x66` → finger → `update 0x6c`) → `commit 0x6e`.
  The template **handle** is returned by the chip in the commit response and is persistent
  in the reader's NVRAM. The decisive detail: the last u32 of the commit tail is the
  output-buffer size — `0x0800` returns the raw blob, `0` **registers** the object and
  returns the handle.
- Verify: `open` → `capture` → finger → `0x73` with the handle array → `result`.

Full notes in [`controlvault/`](controlvault/) (`SESSIONE_CIFRATA.md`,
`ENROLL_PROTOCOL.md`, `ENROLL_RISOLTO.md`, `VERIFY_ANALISI.md`). Documentation is in Italian.

---

## Requirements

- Dell ControlVault2 / BCM5880 reader (`0a5c:5834`). Firmware 4.12.x recommended
  (newer firmware exposes USB config 1 natively, so the legacy `usbcfgfix` kext is not needed).
- Python 3 with [`pyusb`](https://pypi.org/project/pyusb/),
  [`pycryptodome`](https://pypi.org/project/pycryptodome/), and `pyobjc`
  (`pyobjc-framework-Cocoa`, `-Quartz`, `-ApplicationServices`) for the GUI/daemon.
- `libusb` (`brew install libusb`).

```bash
pip3 install pyusb pycryptodome pyobjc-framework-Cocoa pyobjc-framework-Quartz pyobjc-framework-ApplicationServices
```

---

## Repository layout

```
tools/            everything that runs
  cvfp_config.py    paths, timeouts, thresholds (single source of truth)
  fparbiterd.py     arbiter: the only owner of the reader (Unix-socket service)
  fpclient.py       client library used by every other tool
  fpunlock.py       daemon: screen unlock + password-prompt auto-type
  fpauth.py         single-shot auth helper (exit 0 = match) used by PAM
  pam_cvfp.c        PAM module source
  fpmanager.py      GUI (Touch-ID-style) to add/rename/remove/verify fingers
  fpenroll.py / fpverify.py / fpdelete.py   CLI tools (through the arbiter)
  secure.py         SecureSession: handshake/open/capture/update/commit/enroll/verify
  cvcrypto.py       RSA/AES/HMAC session crypto
  install.sh / uninstall.sh / install_pam.sh / install_unlock_agent.sh
  com.cvfp.arbiter.plist / com.cvfp.unlock.plist   LaunchAgent templates
tests/            unit tests with a fake reader (no hardware needed)
controlvault/     USB transport (controlvault.py), protocol docs (IT), runtime data
archivio/         abandoned experiments kept for reference (CryptoTokenKit token)
revault_re/       reverse-engineering scripts for the Linux ToD driver
win_re/           Windows DLL analysis scripts (vendor binaries excluded)
*.cpp / build.sh  legacy usbcfgfix Lilu kext (only for old firmware)
```

> Not included in the repo (see `.gitignore`): the proprietary Broadcom DLL and device
> RSA modulus, raw USB/Frida captures, runtime logs, your personal enrolled template
> (`mac_template.json` — a `.example.json` is provided), and large third-party deps
> (MacKernelSDK, Lilu, the libfprint clone), which you download separately.

---

## Quick install

One command installs the Python dependencies, the PAM module for `sudo`, the
arbiter and screen-unlock LaunchAgents and the FP Manager app:

```bash
bash tools/install.sh
```

It asks for your admin password (for the PAM step) and your login password (stored
in the Keychain, used only to fill the unlock field), and prints the Accessibility
permission step at the end. Skip parts with `--no-pam`, `--no-unlock`, `--no-app`.
Remove everything with `bash tools/uninstall.sh`.

The manual steps below are the equivalent, if you prefer to do them one by one.

---

## Usage

### 1. Enroll (GUI)

```bash
/usr/local/bin/python3 tools/fpmanager.py
```

Click **Aggiungi impronta** and follow the animated fingerprint (lift & touch 8 times;
vary the angle each touch for a more tolerant template). Templates are saved to
`controlvault/mac_template.json`.

Or via CLI: `/usr/local/bin/python3 tools/fpenroll.py [name]`. Enrolling the same finger
two or three times (different placements) makes matching noticeably more reliable.

> **Removing a finger** erases the template from the reader's own chip (`cv_delete_object`,
> opcode `0x0a`) and unlinks it from `sudo`/unlock. CLI: `fpdelete.py <handle>`
> (`--list` shows handles).

### 2. `sudo` with fingerprint

```bash
cd tools
clang -bundle -o pam_cvfp.so pam_cvfp.c -lpam "-DHELPER=\"$PWD/fpauth.py\""
sudo ./install_pam.sh      # backs up and edits /etc/pam.d/sudo
```

Now `sudo` accepts your finger; it falls back to the password on timeout/no-match.

### 3. Screen unlock

```bash
# store your login password in the Keychain (used only to fill the unlock field)
security add-generic-password -U -a "$USER" -s cv-fp-unlock -w
./tools/install_unlock_agent.sh    # installs the arbiter and the unlock daemon
```

Grant **Accessibility** permission to the Python binary when prompted, then log out/in.
Lock the screen (⌃⌘Q) and touch the sensor.

> The daemon stores your login password in the Keychain and fills the unlock field via
> Accessibility — a deliberate trade-off. Review `tools/fpunlock.py` before using it.

---

## Tests

The whole chain (arbiter → socket → client → daemon / `sudo` helper) is covered by unit
tests that run against a **fake reader**, so no hardware or finger is needed:

```bash
/usr/local/bin/python3 -m unittest discover -s tests
```

`tests/fakes.py` scripts what the reader does (finger present, match / no match, stuck
handshake, dropped session…). Run the tests after every change; then confirm on the real
reader with `tools/fpverify.py`.

---

## Security notes — read before relying on this

This is a convenience layer, **not** a Touch ID equivalent. Known trade-offs:

- **Any focused password field counts.** The daemon types your login password whenever a
  fingerprint matches while Secure Input is active — including a password field in a web
  page or another app. Do not touch the sensor while such a field has focus.
- **Your login password is stored in the Keychain** and can be read by any process
  running as your user (`security find-generic-password`).
- **`sudo` runs `tools/fpauth.py` as root**, and that file is owned by your user: any
  process running as you can modify it and become root. For a hardened setup install a
  root-owned copy of `tools/` and compile the PAM module against that path.
- A fingerprint match unlocks for **whoever is logged in**; templates are not per-user.

---

## Archived: CryptoTokenKit token

[`archivio/ctk-token/`](archivio/ctk-token/) contains a working CryptoTokenKit token
extension (sign/decrypt gated by the fingerprint) that was **abandoned**: macOS never
calls `beginAuthForOperation` for a third-party token at the lock screen (so Return must
still be pressed), cold-boot login cannot load the extension, and it needs AMFI disabled.

---

## Credits & disclaimer

Independent reverse-engineering for interoperability on hardware the owner controls.
"ControlVault", "Broadcom" and "Dell" are trademarks of their respective owners; this
project is not affiliated with or endorsed by them, and ships **no** vendor binaries or
keys. Built with help from community work on the ControlVault/libfprint ecosystem.
