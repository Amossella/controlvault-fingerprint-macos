#!/bin/bash
# Genera l'identità del token (RSA-2048 self-signed) e l'header incorporabile.
# La chiave privata NON è nel repo: ognuno genera la propria con questo script,
# PRIMA di compilare. Produce:
#   id/key.der   (chiave privata PKCS#1 DER)   <- usata solo dall'estensione
#   id/cert.der  (certificato X.509 DER)       <- usato solo dall'app host
#   src/IdentityMaterial.h  (base64 di entrambi, #include dai sorgenti)
set -e
cd "$(dirname "$0")"
ROOT=".."

openssl genrsa -out key.pem 2048 2>/dev/null
openssl rsa -in key.pem -outform DER -out key.der 2>/dev/null
openssl req -x509 -new -key key.pem -days 3650 \
    -subj "/CN=ControlVault Fingerprint Token/O=cvfp" -out cert.pem 2>/dev/null
openssl x509 -in cert.pem -outform DER -out cert.der 2>/dev/null

KEY_B64=$(base64 -i key.der | tr -d '\n')
CERT_B64=$(base64 -i cert.der | tr -d '\n')
cat > "$ROOT/src/IdentityMaterial.h" <<EOF
// Materiale di identità auto-firmato (RSA-2048) incorporato come base64.
// GENERATO da id/gen_identity.sh — NON committare (contiene la chiave privata).
// L'estensione usa solo FP_KEY_B64; l'app host usa solo FP_CERT_B64.
#ifndef FP_IDENTITY_MATERIAL_H
#define FP_IDENTITY_MATERIAL_H
#define FP_KEY_B64  @"${KEY_B64}"
#define FP_CERT_B64 @"${CERT_B64}"
#endif
EOF
echo "OK: generati id/key.der, id/cert.der, src/IdentityMaterial.h"
echo "Hash pubkey (per sc_auth pair):"
openssl x509 -in cert.pem -noout -pubkey 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | openssl dgst -sha1 | awk '{print toupper($NF)}'
