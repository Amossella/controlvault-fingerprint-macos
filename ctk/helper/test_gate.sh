#!/bin/bash
# Test positivo del gate impronta del token CTK.
# Esegue una firma tramite il token: il sistema deve chiamare l'helper, che
# attende l'impronta; appoggia il dito sul sensore entro ~25s.
set -e
cd "$(dirname "$0")/.."
SDK="$(xcrun --sdk macosx --show-sdk-path)"

# compila (se serve) un piccolo tester che firma via l'identità del token
BIN=/tmp/cvfp_sign
if [ ! -x "$BIN" ] || [ src/TokenDriver.m -nt "$BIN" ]; then
cat > /tmp/cvfp_sign.m <<'EOF'
#import <Foundation/Foundation.h>
#import <Security/Security.h>
int main(){ @autoreleasepool {
  NSDictionary *q=@{(id)kSecClass:(id)kSecClassIdentity,(id)kSecMatchLimit:(id)kSecMatchLimitOne,
     (id)kSecAttrTokenID:@"com.cvfp.fptoken:fp-1",(id)kSecReturnRef:@YES};
  CFTypeRef idRef=NULL; if(SecItemCopyMatching((__bridge CFDictionaryRef)q,&idRef)!=0){NSLog(@"no identity");return 1;}
  SecKeyRef priv=NULL; SecIdentityCopyPrivateKey((SecIdentityRef)idRef,&priv);
  NSData*m=[@"hello" dataUsingEncoding:NSUTF8StringEncoding]; CFErrorRef e=NULL;
  NSLog(@"Appoggia il dito sul sensore...");
  CFDataRef sig=SecKeyCreateSignature(priv,kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,(__bridge CFDataRef)m,&e);
  if(!sig){NSLog(@"FIRMA RIFIUTATA: %@",(__bridge NSError*)e);return 2;}
  NSLog(@"FIRMA OK: %ld byte (impronta verificata)",(long)CFDataGetLength(sig));
} return 0;}
EOF
clang -fobjc-arc -isysroot "$SDK" -framework Foundation -framework Security /tmp/cvfp_sign.m -o "$BIN"
fi

CLOG=~/Library/Containers/com.cvfp.FPTokenApp.Token/Data/fptoken.log
rm -f "$CLOG"
echo "== lancio firma (tocca il sensore) =="
"$BIN"
echo
echo "== log estensione =="
cat "$CLOG" 2>/dev/null
echo
echo "== stderr helper (fpauth.py) =="
tail -5 /tmp/fphelper.err 2>/dev/null
