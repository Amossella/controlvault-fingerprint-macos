"""Encoder dei comandi ControlVault, ricostruito dal driver Dell (percorso plain).
Formati verificati:
- parametro (InitParam_List @0xe0b0): [encap_type:4 LE][len:4 LE][value:len], type==3 => solo header.
- blob dati (ConstructBlob @0xf070): concatenazione dei parametri, value con padding a multiplo di 4.
- envelope (dalle catture): [seq:4][total:4][cmd_word:4][counter:4][handle:4][status:4][16B zero][data_len:4][blob].
"""
import struct

ENCAP_STRUC = 0; ENCAP_LENVAL_STRUC = 1; ENCAP_LENVAL_PAIR = 2; ENCAP_INOUT = 3

def param(encap_type, value=b""):
    if encap_type == ENCAP_INOUT:
        return struct.pack("<II", encap_type, len(value))  # solo header
    return struct.pack("<II", encap_type, len(value)) + value

def blob(params):
    out = b""
    for encap_type, value in params:
        out += struct.pack("<II", encap_type, len(value))
        if encap_type != ENCAP_INOUT:
            pad = (-len(value)) % 4
            out += value + b"\x00" * pad
    return out

def envelope(cmd_word, data=b"", seq=1, counter=1, handle=0, status=0):
    body = struct.pack("<IIIIII", seq, 0, cmd_word, counter, handle, status)
    body += b"\x00" * 16
    body += struct.pack("<I", len(data)) + data
    total = len(body)
    return body[:4] + struct.pack("<I", total) + body[8:]

def u32(v): return struct.pack("<I", v)

if __name__ == "__main__":
    # VALIDAZIONE: ricostruire l'init 0x82 catturato
    captured = bytes.fromhex("010000003800000082004000010000000000000000000000000000000000000000000000000000000c000000000000000400000000000000")
    data = blob([(ENCAP_STRUC, u32(0))])          # 1 param: type0, len4, value=0
    built = envelope(0x00400082, data, seq=1, counter=1)
    print("init atteso :", captured.hex())
    print("init ricostr:", built.hex())
    print("IDENTICO:", built == captured)
