"""dumpfn.py - disassemble a named function (bounded by the real symbol end) and annotate bl targets
usage: python tools/dumpfn.py <name> [maxlen]
"""
import sys
import capstone
from elftools.elf.elffile import ELFFile

elf = ELFFile(open('firmware/vmlinux.elf', 'rb'))
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
    lo, hi, best = 0, len(sorted_addrs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if sorted_addrs[mid] <= addr:
            best, lo = sorted_addrs[mid], mid + 1
        else:
            hi = mid - 1
    return addr2name.get(best, '?') + f'+{addr-best:#x}' if best is not None else '?'


name = sys.argv[1]
maxlen = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x800
a = sym.get(name)
if a is None:
    print('MISSING', name)
    print([k for k in sym if name.split('.')[0] in k])
    sys.exit(1)
idx = sorted_addrs.index(a)
sz = min(maxlen, sorted_addrs[idx + 1] - a) if idx + 1 < len(sorted_addrs) else maxlen
print(f'=== {name} @{a:#x}  size={sz:#x} (next sym: {owner(a+sz)})')
for i in md.disasm(data[a - vbase:a - vbase + sz], a):
    line = f'+{i.address-a:#06x}  {i.mnemonic:9s} {i.op_str}'
    if i.mnemonic in ('bl', 'b') and i.op_str.startswith('#'):
        t = int(i.op_str[1:], 16)
        line += f'      ; -> {owner(t)}'
    print(line)
