// Frida hook per catturare la crittografia di ControlVault (bipdll.dll in HostControlService.exe)
// Logga: CryptHashData (cosa si hasha = nonce), CryptSetKeyParam (IV), CryptImportKey (chiave),
// CryptEncrypt/CryptDecrypt (plaintext/ciphertext = formato comando sicuro),
// e le CNG BCryptEncrypt/NCryptDeriveKey/NCryptSecretAgreement se usate.
// Uso:  frida -n HostControlService.exe -l frida_hook.js  > crypto_log.txt  2>&1

function hex(ptr, len) {
  if (ptr.isNull() || len <= 0) return "(vuoto)";
  if (len > 4096) len = 4096;
  try { return hexdump(ptr, { length: len, header: false, ansi: false }); }
  catch (e) { return "(illeggibile)"; }
}
function u32(ptr) { try { return ptr.readU32(); } catch (e) { return -1; } }

function hook(mod, fn, onEnter, onLeave) {
  var a = Module.findExportByName(mod, fn);
  if (a === null) { console.log("[!] non trovata:", mod + "!" + fn); return; }
  Interceptor.attach(a, { onEnter: onEnter, onLeave: onLeave });
  console.log("[+] hook:", mod + "!" + fn, "@", a);
}

// --- CryptoAPI legacy (il percorso usato) ---
hook("advapi32.dll", "CryptImportKey", function (args) {
  // (hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey)
  var len = args[2].toInt32();
  console.log("\n=== CryptImportKey  len=" + len + " ===\n" + hex(args[1], len));
});

hook("advapi32.dll", "CryptCreateHash", function (args) {
  // (hProv, Algid, hKey, dwFlags, phHash)
  console.log("\n=== CryptCreateHash Algid=0x" + args[1].toInt32().toString(16) + " ===");
});

hook("advapi32.dll", "CryptHashData", function (args) {
  // (hHash, pbData, dwDataLen, dwFlags)  <-- QUESTO rivela i nonce hashati
  var len = args[2].toInt32();
  console.log("\n=== CryptHashData  len=" + len + "  (DATI HASHATI = nonce/chiave) ===\n" + hex(args[1], len));
});

hook("advapi32.dll", "CryptSetKeyParam", function (args) {
  // (hKey, dwParam, pbData, dwFlags)  dwParam 1=KP_IV, 4=KP_MODE
  var p = args[1].toInt32();
  var name = (p === 1) ? "KP_IV" : (p === 4) ? "KP_MODE" : ("0x" + p.toString(16));
  console.log("\n=== CryptSetKeyParam  " + name + " ===\n" + hex(args[2], p === 1 ? 16 : 4));
});

hook("advapi32.dll", "CryptEncrypt", function (args) {
  // (hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
  this.pb = args[4]; this.plen = args[5];
  var l = u32(this.plen);
  console.log("\n=== CryptEncrypt  PLAINTEXT  len=" + l + " ===\n" + hex(this.pb, l));
}, function (ret) {
  var l = u32(this.plen);
  console.log("--- CryptEncrypt  CIPHERTEXT len=" + l + " ---\n" + hex(this.pb, l));
});

hook("advapi32.dll", "CryptDecrypt", function (args) {
  this.pb = args[4]; this.plen = args[5];
  console.log("\n=== CryptDecrypt  IN len=" + u32(this.plen) + " ===\n" + hex(this.pb, u32(this.plen)));
}, function (ret) {
  console.log("--- CryptDecrypt  OUT len=" + u32(this.plen) + " ---\n" + hex(this.pb, u32(this.plen)));
});

// --- CNG (se il device usasse il percorso moderno) ---
hook("bcrypt.dll", "BCryptEncrypt", function (args) {
  var l = args[2].toInt32();
  console.log("\n=== BCryptEncrypt IN len=" + l + " ===\n" + hex(args[1], l));
});
hook("ncrypt.dll", "NCryptSecretAgreement", function (args) {
  console.log("\n=== NCryptSecretAgreement (ECDH) ===");
});
hook("ncrypt.dll", "NCryptDeriveKey", function (args) {
  console.log("\n=== NCryptDeriveKey (KDF) ===");
});

console.log("\n[*] Hook pronti. Ora fai un ENROLL dell'impronta in Windows Hello.\n");
