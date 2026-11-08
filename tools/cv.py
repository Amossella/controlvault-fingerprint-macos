"""Client minimale per il ControlVault BCM5880 (0a5c:5834), interfaccia 0 (USH).
Envelope: [seq:4LE][total_len:4LE][cmd_word:4LE][counter:4LE] + 24B zero + [data_len:4LE][data].
Scambio: OUT su 0x01, notifica su 0x85 (interrupt), risposta su 0x81 (bulk).
"""
import struct, usb.core, usb.util, usb.backend.libusb1, libusb_package

VID, PID = 0x0a5c, 0x5834
EP_OUT, EP_IN, EP_INT = 0x01, 0x81, 0x85


def open_dev():
    be = usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=be)
    if dev is None:
        raise SystemExit("device 0a5c:5834 non trovato")
    usb.util.claim_interface(dev, 0)
    return dev


def envelope(cmd_word, data=b"", seq=1, counter=0):
    body = struct.pack("<IIII", seq, 0, cmd_word, counter) + b"\x00" * 24
    body += struct.pack("<I", len(data)) + data
    total = len(body)
    return body[:4] + struct.pack("<I", total) + body[8:]


def xfer(dev, pkt, label="", timeout=4000):
    n = dev.write(EP_OUT, pkt, timeout=timeout)
    try:
        notif = bytes(dev.read(EP_INT, 16, timeout=timeout))
    except usb.core.USBError:
        notif = b""
    rlen = struct.unpack_from("<I", notif, 4)[0] if len(notif) >= 8 else 512
    resp = bytes(dev.read(EP_IN, max(rlen, 64), timeout=timeout))
    if label:
        print("%-12s OUT %3dB -> notif %s  IN %3dB %s" % (label, n, notif.hex(), len(resp), resp[:24].hex()))
    return resp


def parse_resp(resp):
    seq, total, cmd, counter = struct.unpack_from("<IIII", resp, 0)
    dlen = struct.unpack_from("<I", resp, 40)[0] if len(resp) >= 44 else 0
    return dict(seq=seq, cmd=cmd, counter=counter, data=resp[44:44 + dlen])


if __name__ == "__main__":
    import sys
    dev = open_dev()
    print("configurazione attiva:", bytes(dev.ctrl_transfer(0x80, 8, 0, 0, 1, 1000))[0])
    # init: comando 0x00400082, data = 04 00 00 00 (4 byte come nella cattura 00-init)
    init = bytes.fromhex("010000003800000082004000010000000000000000000000000000000000000000000000000000000c000000000000000400000000000000")
    r = xfer(dev, init, "init 0x82")
    p = parse_resp(r)
    print("  risposta cmd=%08x counter=%d data=%s" % (p["cmd"], p["counter"], p["data"].hex()))
    usb.util.release_interface(dev, 0)
