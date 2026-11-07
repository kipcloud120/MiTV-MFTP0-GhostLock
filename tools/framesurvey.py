"""framesurvey.py - walk candidate syscall chains and compute the stack-buffer depth relative to S (entry SP)
usage: python framesurvey.py sym1 sym2 ...
output: frame size and bl targets (with symbol names) per symbol
"""
import sys
import capstone
from elftools.elf.elffile import ELFFile

ELF = 'firmware/vmlinux.elf'
elf = ELFFile(open(ELF, 'rb'))
st = elf.get_section_by_name('.symtab')
sym = {}
for s in st.iter_symbols():
    if s.name and s['st_value']:
        sym.setdefault(s.name, s['st_value'])
addr2name = {}
for n, a in sym.items():
    addr2name.setdefault(a, n)
sorted_addrs = sorted(addr2name)

seg = max([sp for sp in elf.iter_segments() if sp['p_type'] == 'PT_LOAD'],
          key=lambda s: s['p_filesz'])
data, vbase = seg.data(), seg['p_vaddr']
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def owner(addr):
    """return the nearest symbol name <= addr"""
    lo, hi = 0, len(sorted_addrs) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if sorted_addrs[mid] <= addr:
            best = sorted_addrs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return addr2name.get(best, '?'), best


def frame(name):
    a = sym.get(name)
    if not a:
        return None
    ins = list(md.disasm(data[a - vbase:a - vbase + 0x30], a))
    if not ins:
        return None
    first = ins[0]
    if first.mnemonic == 'stp' and first.op_str.startswith('x29, x30, [sp, #-'):
        size = int(first.op_str.split('#-')[1].rstrip(']!'), 16)
        return size
    if first.mnemonic == 'sub' and first.op_str.startswith('sp, sp, #'):
        return int(first.op_str.split('#')[1], 16)
    return 0


def calls(name, size=0x800):
    a = sym.get(name)
    if not a:
        return []
    out = []
    for i in md.disasm(data[a - vbase:a - vbase + size], a):
        if i.mnemonic == 'bl' and i.op_str.startswith('#'):
            tgt = int(i.op_str[1:], 16)
            nm, _ = owner(tgt)
            out.append((i.address, tgt, nm))
    return out


for name in sys.argv[1:]:
    f = frame(name)
    a = sym.get(name)
    print(f'=== {name} @ {hex(a) if a else None}  frame={hex(f) if f else f}')
    for site, tgt, nm in calls(name):
        if nm != name and not nm.startswith('__sanitizer'):
            print(f'    +{site - a:#06x} bl {hex(tgt)} ({nm})')
