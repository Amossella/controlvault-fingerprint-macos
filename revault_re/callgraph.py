"""Grafo chiamate risolto coi nomi esportati (dynsym) del .so."""
import sys, struct
sys.path.insert(0, ".")
from elfmap import ELF, scan_calls, plt_map

elf = ELF(sys.argv[1])

def defined_syms(elf):
    ds, dstr = elf.by[".dynsym"], elf.by[".dynstr"]
    out = {}
    for i in range(ds["size"] // 24):
        o = ds["off"] + i*24
        name, info, other, shndx, val, size = struct.unpack_from("<IBBHQQ", elf.d, o)
        if shndx != 0 and val:
            e = elf.d.index(b"\0", dstr["off"]+name)
            nm = elf.d[dstr["off"]+name:e].decode("latin1")
            if nm: out[val] = nm
    return out

syms = defined_syms(elf)           # addr -> name (funzioni/dati definiti)
pm = plt_map(elf)                  # addr plt -> nome importato
calls = scan_calls(elf)
# ordina simboli per trovare la funzione che contiene un indirizzo
addrs = sorted(syms)
import bisect
def fn_of(va):
    i = bisect.bisect_right(addrs, va) - 1
    return syms[addrs[i]] if i >= 0 else "?"
def name_of_target(t):
    return syms.get(t) or pm.get(t) or ("sub_%x" % t)

want = sys.argv[2:] if len(sys.argv) > 2 else []
for fn in want:
    base = next((a for a,n in syms.items() if n == fn), None)
    if base is None:
        print("## %s: non trovato" % fn); continue
    end = addrs[bisect.bisect_right(addrs, base)] if bisect.bisect_right(addrs, base) < len(addrs) else base+0x1000
    seq = [(c, name_of_target(t)) for c,t in calls if base <= c < end]
    print("## %s @ %x (len %x): %d chiamate" % (fn, base, end-base, len(seq)))
    for c, n in seq:
        print("   %05x -> %s" % (c, n))
