# Token CryptoTokenKit sbloccato dall'impronta (ControlVault)

Estensione **CryptoTokenKit** di terze parti che espone a macOS un'identità
(certificato + chiave RSA-2048) utilizzabile per **login / sblocco / sudo / dialoghi
di autorizzazione nativi**. L'operazione di firma della chiave è **gated
dall'impronta** letta dal ControlVault: nessuna firma senza un dito riconosciuto.

A differenza del demone `tools/fpunlock.py` (che auto-digita la password nei
campi tramite AX/CGEvent), qui l'integrazione è **nativa**: è il sistema a chiedere
il token, e il token firma solo dopo il match dell'impronta.

## Componenti

| File | Ruolo |
|------|------|
| `src/TokenDriver.m` | Estensione: `FPTokenDriver` / `FPToken` / `FPTokenSession`. Firma RSA + gate impronta in `signData` (e `beginAuthForOperation`). |
| `src/main.m` | App host: popola la token-config `fp-1` con cert+chiave (constraint `SignData = "fp"`). |
| `src/FPHelperProtocol.h` | Protocollo XPC condiviso estensione ⇄ helper. |
| `helper/fphelper.m` | **LaunchAgent non sandbox** che possiede il Mach service `com.cvfp.fphelper` ed esegue `tools/fpauth.py` (verifica impronta one-shot). |
| `helper/com.cvfp.fphelper.plist` | LaunchAgent dell'helper. |
| `id/gen_identity.sh` | Genera la chiave privata + certificato + `src/IdentityMaterial.h`. **La chiave NON è nel repo.** |
| `token-full.entitlements` | `app-sandbox` + `com.apple.token` + `mach-lookup` verso l'helper. |
| `host.entitlements` | `com.apple.private.ctk.configuration-allowed-for-bundles`. |

## Prerequisiti

- **AMFI disattivato** (boot-arg OpenCore `amfi_get_out_of_my_way=1`): serve perché
  la firma usa entitlement ristretti/privati (`com.apple.token`, mach-lookup
  exception) con cert Apple Development gratuito, senza provisioning profile che li
  conceda. Su un Mac con Developer ID a pagamento questo passo non serve.
- **Xcode** (per la firma Apple Development) + un Apple ID gratuito nel team.
- Lettore ControlVault funzionante con impronta registrata (`tools/fpenroll.py`
  → `controlvault/mac_template.json`).

## Build & install

```bash
# 1) genera l'identità (una volta): chiave privata locale, mai nel repo
ctk/id/gen_identity.sh                     # stampa anche l'hash pubkey per sc_auth

# 2) build firmata (Apple Development) SENZA le entitlement ristrette nel profilo
cd ctk
xcodebuild -project FPToken.xcodeproj -scheme FPTokenApp -configuration Release \
  -derivedDataPath build-xc -allowProvisioningUpdates CODE_SIGN_ENTITLEMENTS="" build

# 3) re-firma post-hoc aggiungendo le entitlement (AMFI off le onora)
APP=build-xc/Build/Products/Release/FPTokenApp.app
ID="Apple Development: <tuo-id>"
codesign --force --sign "$ID" --entitlements token-full.entitlements "$APP/Contents/PlugIns/FPToken.appex"
codesign --force --sign "$ID" --entitlements host.entitlements "$APP"

# 4) installa + registra, poi lancia l'host per creare la token-config
cp -R "$APP" /Applications/FPTokenApp.app
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f -R -trusted /Applications/FPTokenApp.app
/Applications/FPTokenApp.app/Contents/MacOS/FPTokenApp

# 5) helper impronta (LaunchAgent)
clang -fobjc-arc -framework Foundation ctk/helper/fphelper.m -o ctk/helper/fphelper
codesign --force --sign - ctk/helper/fphelper
cp ctk/helper/com.cvfp.fphelper.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.cvfp.fphelper.plist
```

## Verifica

```bash
sc_auth identities           # elenca "ControlVault Fingerprint" (Unpaired)
ctk/helper/test_gate.sh      # firma di prova: richiede il dito, poi "FIRMA OK"
```

## Abilitare login / sblocco / sudo nativi

```bash
sudo sc_auth pair -u "$(whoami)" -h <HASH_PUBKEY>   # additivo, reversibile con unpair
```

> ⚠️ **Contesa USB**: il demone `com.cvfp.unlock` (`fpunlock.py`) tiene il lettore in
> continuo. Finché è attivo l'helper non riesce a leggere. Per ora si usa uno alla
> volta (`launchctl bootout gui/$(id -u)/com.cvfp.unlock` prima di testare il token).
> Soluzione pulita futura: un unico arbitro USB.

## Note di sicurezza

- La chiave privata del token è nel solo `src/IdentityMaterial.h` locale (git-ignored).
- Il gate è applicato **dentro `signData`**: una `SecKeyCreateSignature` diretta non
  fa sempre scattare `beginAuthForOperation`, quindi il controllo lì sarebbe aggirabile.
