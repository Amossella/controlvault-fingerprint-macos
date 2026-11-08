"""Parser pcap usbmon (LINKTYPE_USB_LINUX_MMAPPED=220) + decodifica envelope CV."""
import struct, sys

def packets(path):
    d = open(path, "rb").read()
    off = 24  # global header
    while off + 16 <= len(d):
        ts_s, ts_u, incl, orig = struct.unpack_from("<IIII", d, off)
        off += 16
        pkt = d[off:off+incl]; off += incl
        if len(pkt) < 64: continue
        urb_id, ev, xfer, epnum, devnum = struct.unpack_from("<QBBBB", pkt, 0)
        busnum, = struct.unpack_from("<H", pkt, 12)
        status, = struct.unpack_from("<i", pkt, 28)
        length, lencap = struct.unpack_from("<II", pkt, 32)
        data = pkt[64:64+lencap]
        yield dict(ts=ts_s+ts_u/1e6, ev=chr(ev), xfer=xfer, ep=epnum, dev=devnum,
                   bus=busnum, status=status, length=length, data=data)

XFER={0:"ISO",1:"INT",2:"CTRL",3:"BULK"}

def cv_fields(pl):
    if len(pl) < 44: return None
    seq,total,cmd,cnt,handle,st = struct.unpack_from("<IIIIII", pl, 0)
    dlen = struct.unpack_from("<I", pl, 40)[0]
    return dict(cmd=cmd, cnt=cnt, handle=handle, st=st, dlen=dlen, data=pl[44:44+dlen])

if __name__ == "__main__":
    path=sys.argv[1]; dev=int(sys.argv[2]) if len(sys.argv)>2 else None
    t0=None
    for p in packets(path):
        if dev is not None and p["dev"]!=dev: continue
        if p["xfer"] not in (1,3): continue      # INT o BULK
        if not p["data"]: continue
        if t0 is None: t0=p["ts"]
        d="OUT" if (p["ep"]&0x80)==0 else "IN "
        pl=p["data"]
        cv=cv_fields(pl) if len(pl)>=44 else None
        tag=""
        if cv: tag="cmd=%08x cnt=%d h=%08x st=%d dlen=%d" % (cv["cmd"],cv["cnt"],cv["handle"],cv["st"],cv["dlen"])
        print("%8.3f %s ep=%02x %s len=%4d %s %s" % (p["ts"]-t0, XFER[p["xfer"]], p["ep"], d, len(pl), tag, pl[:16].hex()))
