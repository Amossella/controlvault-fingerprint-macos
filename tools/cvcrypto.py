"""Crittografia sessione ControlVault (percorso RSA/MSCAPI) — VERIFICATA sui byte reali
del driver Windows bipdll.dll (cattura Frida, 2026-11-08).

Handshake:
- 0x23: device -> chiave pubblica RSA-2048 (256B della risposta, LITTLE-ENDIAN = modulo),
  esponente 0x10001; + DEVICE NONCE (20B a offset 296..315). Host manda host_nonce (20B).
- 0x24 = RSA-PKCS1v1.5( host_nonce ) little-endian.
Chiavi (VERIFICATE):
- AES-128 key = SHA1( device_nonce[20] || host_nonce[20] )[:16]
- HMAC key    = SHA1( b"CV secure session blob\\x00" )            (costante)
Comando sicuro (VERIFICATO: riproduce il ciphertext catturato):
- envelope header 44B con IV (16B) a offset 24..39
- mac = HMAC-SHA1( hmac_key, header(44) || data )
- plaintext = data || mac(20) || zero-pad a multiplo di 16
- ciphertext = AES-128-CBC( plaintext, aes_key, IV ) + padding PKCS7
- sul filo: header(44, IV incluso) || ciphertext
"""
import os, struct, hashlib, hmac
try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

BLOB_STR = b"CV secure session blob\x00"
E = 0x10001

# ---- handshake RSA ----
def device_pubkey_from_0x23(resp_data):
    n = int.from_bytes(resp_data[:256], "little")
    return n

def device_nonce_from_0x23(resp_data):
    return resp_data[296:316]

def rsa_pkcs1v15_encrypt_le(msg, n, e=E):
    k = 256
    ps_len = k - 3 - len(msg)
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b[0] != 0: ps.append(b[0])
    em = b"\x00\x02" + bytes(ps) + b"\x00" + msg
    c = pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "little")

# ---- chiavi di sessione ----
def session_keys(host_nonce, device_nonce):
    aes_key = hashlib.sha1(device_nonce + host_nonce).digest()[:16]
    hmac_key = hashlib.sha1(BLOB_STR).digest()
    return aes_key, hmac_key

# ---- comando sicuro ----
def build_secure_envelope(cmd_word, data, aes_key, hmac_key, counter=2, handle=0, seq=1, iv=None, hmac_seq=0):
    # VERIFICATO sui byte del driver (self-test riproduce il ciphertext catturato).
    # hmac_seq = contatore di sequenza u32 della sessione sicura (open=0, poi ++ per operazione);
    # entra SEMPRE in coda all'input HMAC (header||data||hmac_seq), non e' padding.
    if AES is None: raise RuntimeError("pycryptodome non installato")
    if iv is None:
        iv = os.urandom(16)
    # dimensione ciphertext: pad16(len(data)+20) poi +16 PKCS7
    pt_len = len(data) + 20
    pt_len += (-pt_len) % 16
    ct_len = pt_len + 16
    total = 44 + ct_len
    header = struct.pack("<IIIIII", seq, total, cmd_word, counter, handle, 0) + iv + struct.pack("<I", len(data))
    # HMAC-SHA1 su header(44) || data || seq_u32_LE  (VERIFICATO sui byte del driver Windows)
    mac = hmac.new(hmac_key, header + data + struct.pack("<I", hmac_seq), hashlib.sha1).digest()
    # plaintext = data || mac || zero-pad a 16, poi PKCS7
    pt = data + mac
    pt += b"\x00" * ((-len(pt)) % 16)
    pt += bytes([16]) * 16
    ct = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pt)
    return header + ct

def decrypt_secure_response(resp, aes_key):
    # resp: header 44B (IV a offset 24) + ciphertext
    iv = resp[24:40]; ct = resp[44:]
    pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct)
    return pt
