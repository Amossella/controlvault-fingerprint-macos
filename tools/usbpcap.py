"""Parser minimale per catture USBPcap (pcapng) — nessuna dipendenza."""
import struct, sys

XFER = {0: "ISO", 1: "INT", 2: "CTRL", 3: "BULK", 0xFE: "IRP", 0xFF: "?"}
TARGET_DEV = 5  # indirizzo del 5880 nelle catture Windows


def packets(path):
    data = open(path, "rb").read()
    off = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, off)
        body = data[off + 8: off + blen - 4]
        if btype == 6:  # Enhanced Packet Block
            _, th, tl, caplen, _ = struct.unpack_from("<IIIII", body, 0)
            yield ((th << 32) | tl) / 1e6, body[20:20 + caplen]
        off += blen


def parse(pkt):
    hlen, irp, status, func, info, bus, dev, ep, xfer, dlen = struct.unpack_from("<HQIHBHHBBI", pkt, 0)
    stage = pkt[27] if xfer == 2 and hlen >= 28 else None
    return dict(status=status, dev=dev, ep=ep, xfer=XFER.get(xfer, xfer), stage=stage, payload=pkt[hlen:])


def transfers(path, dev=TARGET_DEV):
    """Trasferimenti bulk/interrupt con dati verso/dal device, in ordine: (t, ep, payload)."""
    pk = [(ts, parse(r)) for ts, r in packets(path)]
    t0 = pk[0][0]
    for ts, p in pk:
        if p["dev"] == dev and p["xfer"] in ("BULK", "INT") and p["payload"]:
            yield ts - t0, p["ep"], p["payload"]


if __name__ == "__main__":
    full = "-f" in sys.argv
    for i, (t, ep, pl) in enumerate(transfers(sys.argv[1]), 1):
        d = "OUT" if ep < 0x80 else "IN "
        h = pl.hex() if full or len(pl) <= 48 else pl[:48].hex() + "…"
        print("%3d %8.3f ep=%02x %s len=%4d %s" % (i, t, ep, d, len(pl), h))
