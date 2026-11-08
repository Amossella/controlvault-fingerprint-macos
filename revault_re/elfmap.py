"""Scanner statico (no deps) per ELF x86-64 PIC:
- mappa i riferimenti RIP-relative a stringhe (lea reg,[rip+disp])
- estrae le chiamate (e8 rel32) per ricostruire il grafo delle chiamate
Serve a etichettare le funzioni dalle loro stringhe di log 'Enter cv_...'.
"""
import struct, sys, bisect

class ELF:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        assert self.d[:4] == b"\x7fELF" and self.d[4] == 2, "non ELF64"
        e_shoff = struct.unpack_from("<Q", self.d, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", self.d, 0x3a)
        self.secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", self.d, o)
            self.secs.append(dict(name=name, type=typ, addr=addr, off=off, size=size))
        stro = self.secs[e_shstrndx]["off"]
        for s in self.secs:
            e = self.d.index(b"\0", stro + s["name"])
            s["nm"] = self.d[stro + s["name"]:e].decode()
        self.by = {s["nm"]: s for s in self.secs}

    def sec(self, nm): return self.by[nm]

    def vaddr_to_off(self, va):
        for s in self.secs:
            if s["addr"] and s["addr"] <= va < s["addr"] + s["size"] and s["type"] != 8:
                return s["off"] + (va - s["addr"])
        return None

    def cstr_at(self, va):
        off = self.vaddr_to_off(va)
        if off is None: return None
        e = self.d.index(b"\0", off)
        try: return self.d[off:e].decode("latin1")
        except Exception: return None


def scan_lea_strings(elf):
    """Trova lea reg,[rip+disp32] che puntano dentro .rodata/.data.rel.ro -> (insn_va, string)."""
    text = elf.sec(".text"); base = text["addr"]; data = elf.d[text["off"]:text["off"]+text["size"]]
    ro = [elf.by[n] for n in (".rodata", ".data.rel.ro") if n in elf.by]
    def in_ro(va): return any(s["addr"] <= va < s["addr"]+s["size"] for s in ro)
    out = {}
    i = 0
    while i < len(data) - 7:
        b0, b1 = data[i], data[i+1]
        # REX.W (0x48/0x4c) + 8d (lea) + modrm con mod=00 rm=101 (RIP-relative)
        if b0 in (0x48, 0x4c) and b1 == 0x8d and (data[i+2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i+3)[0]
            va = base + i; tgt = va + 7 + disp
            if in_ro(tgt):
                s = elf.cstr_at(tgt)
                if s and s.isprintable() and len(s) >= 3:
                    out[va] = s
            i += 7; continue
        i += 1
    return out


def scan_calls(elf):
    """Estrae call near rel32 (e8) dentro .text -> lista (call_va, target_va).
    I target possono cadere in .plt/.plt.sec (prima di .text), quindi accettiamo
    tutto l'intervallo eseguibile [min(plt), end(text))."""
    text = elf.sec(".text"); base = text["addr"]; data = elf.d[text["off"]:text["off"]+text["size"]]
    lo = min(elf.by[n]["addr"] for n in (".plt", ".plt.sec", ".text") if n in elf.by)
    hi = text["addr"] + text["size"]
    calls = []
    for i in range(len(data) - 5):
        if data[i] == 0xe8:
            rel = struct.unpack_from("<i", data, i+1)[0]
            tgt = base + i + 5 + rel
            if lo <= tgt < hi:
                calls.append((base + i, tgt))
    return calls


def dynsyms(elf):
    ds, dstr = elf.by[".dynsym"], elf.by[".dynstr"]
    n = ds["size"] // 24; out = []
    for i in range(n):
        o = ds["off"] + i*24
        name, = struct.unpack_from("<I", elf.d, o)
        e = elf.d.index(b"\0", dstr["off"]+name)
        out.append(elf.d[dstr["off"]+name:e].decode("latin1"))
    return out

def plt_map(elf):
    """VA dell'entry .plt.sec -> nome simbolo importato, via .rela.plt."""
    syms = dynsyms(elf)
    rp = elf.by.get(".rela.plt")
    if not rp: return {}
    plt = elf.by.get(".plt.sec") or elf.by.get(".plt")
    stride = 16; m = {}
    nrel = rp["size"] // 24
    for i in range(nrel):
        o = rp["off"] + i*24
        r_off, r_info, r_add = struct.unpack_from("<QQq", elf.d, o)
        symidx = r_info >> 32
        va = plt["addr"] + i*stride
        m[va] = syms[symidx] if symidx < len(syms) else "?"
    return m

def linear(elf, start, end):
    """Eventi in ordine di indirizzo tra [start,end): stringhe e chiamate risolte."""
    leas = scan_lea_strings(elf)
    calls = dict(scan_calls(elf))
    pm = plt_map(elf)
    ev = []
    for va, s in leas.items():
        if start <= va < end: ev.append((va, "STR ", repr(s)))
    for va, tgt in calls.items():
        if start <= va < end:
            ev.append((va, "CALL", pm.get(tgt, "sub_%x" % tgt)))
    for va, k, v in sorted(ev):
        print("  %08x %s %s" % (va, k, v))

if __name__ == "__main__":
    elf = ELF(sys.argv[1])
    if len(sys.argv) > 3 and sys.argv[2] == "--range":
        a, b = sys.argv[3].split(":"); linear(elf, int(a,16), int(b,16)); sys.exit()
    print("sezioni:", {n: hex(elf.by[n]["addr"]) for n in (".text",".rodata",".data.rel.ro",".plt",".plt.sec") if n in elf.by})
    leas = scan_lea_strings(elf)
    print("string-xref trovati:", len(leas))
    q = sys.argv[2] if len(sys.argv) > 2 else None
    if q:
        for va, s in sorted(leas.items()):
            if q.lower() in s.lower():
                print("  %08x -> %r" % (va, s))
