"""Mini analizzatore PE x64: sezioni, xref stringhe (lea rip), import IAT e call site."""
import struct, sys, bisect

class PE:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        e_lfanew = struct.unpack_from("<I", self.d, 0x3c)[0]
        assert self.d[e_lfanew:e_lfanew+4] == b"PE\0\0"
        coff = e_lfanew + 4
        machine, nsec, _, _, _, optsz, _ = struct.unpack_from("<HHIIIHH", self.d, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", self.d, opt)[0]  # 0x20b = PE32+
        self.image_base = struct.unpack_from("<Q", self.d, opt+24)[0]
        # data directories: import table = index 1
        dd_off = opt + 112
        self.imp_rva, self.imp_sz = struct.unpack_from("<II", self.d, dd_off + 1*8)
        self.secs = []
        so = opt + optsz
        for i in range(nsec):
            o = so + i*40
            name = self.d[o:o+8].rstrip(b"\0").decode("latin1")
            vsz, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", self.d, o+8)
            self.secs.append(dict(name=name, va=vaddr, vsz=vsz, raw=rawptr, rawsz=rawsz))

    def rva_to_off(self, rva):
        for s in self.secs:
            if s["va"] <= rva < s["va"]+max(s["vsz"], s["rawsz"]):
                return s["raw"] + (rva - s["va"])
        return None
    def off_to_rva(self, off):
        for s in self.secs:
            if s["raw"] <= off < s["raw"]+s["rawsz"]:
                return s["va"] + (off - s["raw"])
        return None
    def sec(self, nm): return next(s for s in self.secs if s["nm"]==nm) if any(s["nm"]==nm for s in self.secs) else None
    def secof(self, nm):
        for s in self.secs:
            if s["name"]==nm: return s
        return None
    def cstr(self, rva):
        off=self.rva_to_off(rva)
        if off is None: return None
        e=self.d.find(b"\0",off)
        if e<0 or e-off>512: return None
        try: return self.d[off:e].decode("latin1")
        except: return None

def imports(pe):
    """RVA della IAT entry -> nome funzione importata."""
    out={}
    off=pe.rva_to_off(pe.imp_rva)
    i=0
    while True:
        o=off+i*20
        oft, tstamp, fwd, nameRVA, firstThunk = struct.unpack_from("<IIIII", pe.d, o)
        if oft==0 and nameRVA==0 and firstThunk==0: break
        dll = pe.cstr(nameRVA) or "?"
        thunk = oft or firstThunk
        to=pe.rva_to_off(thunk); ia=pe.rva_to_off(firstThunk)
        j=0
        while True:
            val=struct.unpack_from("<Q", pe.d, to+j*8)[0]
            if val==0: break
            iat_rva = firstThunk + j*8
            if not (val & (1<<63)):
                nm=pe.cstr(val+2)
                out[iat_rva]="%s!%s"%(dll,nm)
            j+=1
        i+=1
    return out

def text_scan(pe):
    """lea rip-relative -> stringhe in .rdata; call [rip+IAT] -> import."""
    t=pe.secof(".text"); base=t["va"]; data=pe.d[t["raw"]:t["raw"]+t["rawsz"]]
    rdata=[s for s in pe.secs if s["name"] in (".rdata",".data")]
    imp=imports(pe)
    strxref={}; callimp=[]
    i=0
    while i < len(data)-7:
        b0,b1=data[i],data[i+1]
        # lea reg,[rip+disp32]: 48/4c 8d /r mod=00 rm=101
        if b0 in (0x48,0x4c) and b1==0x8d and (data[i+2]&0xc7)==0x05:
            disp=struct.unpack_from("<i",data,i+3)[0]
            rva=base+i; tgt=(rva+7+disp)
            s=pe.cstr(tgt)
            if s and len(s)>=3 and s.isprintable(): strxref[rva]=s
            i+=7; continue
        # call qword [rip+disp32]: ff 15 disp32
        if b0==0xff and b1==0x15:
            disp=struct.unpack_from("<i",data,i+2)[0]
            rva=base+i; tgt=rva+6+disp
            if tgt in imp: callimp.append((rva, imp[tgt]))
            i+=6; continue
        i+=1
    return strxref, callimp, imp

if __name__=="__main__":
    pe=PE(sys.argv[1])
    print("image_base %x sezioni: %s" % (pe.image_base, [(s["name"],hex(s["va"])) for s in pe.secs]))
    sx,ci,imp=text_scan(pe)
    print("string-xref:",len(sx)," call-import:",len(ci)," imports:",len(imp))
    q=sys.argv[2] if len(sys.argv)>2 else None
    if q:
        for va,s in sorted(sx.items()):
            if q.lower() in s.lower(): print("  STR %08x -> %r"%(va,s))
        for va,n in sorted(ci):
            if q.lower() in n.lower(): print("  CALL %08x -> %s"%(va,n))
