"""chainpath.py - confirm the sched_setattr -> PI chain entry point: who calls adjust_prio_chain and which chwalk value is passed
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
NOISE = ('_mcount', '__stack_chk_fail')


def owner(addr):
    lo, hi, best = 0, len(sorted_addrs) - 1, None
    while lo <= hi:
        mid = (lo, hi)[(lo + hi) // 2 <= hi]
        mid = (lo + hi) // 2
        if sorted_addrs[mid] <= addr:
            best, lo = sorted_addrs[mid], mid + 1
        else:
            hi = mid - 1
    return addr2name.get(best, '?')


def dis(name, span=0x400, show=True):
    a = sym.get(name)
    if not a:
        print(f'--- {name}: MISSING')
        return
    sz = span
    # function size: up to the next symbol
    idx = sorted_addrs.index(a)
    if idx + 1 < len(sorted_addrs):
        sz = min(span, sorted_addrs[idx + 1] - a)
    ins = list(md.disasm(data[a - vbase:a - vbase + sz], a))
    print(f'=== {name} @{a:#x} size={sz:#x}')
    for i in ins:
        line = f'  +{i.address-a:#06x} {i.mnemonic} {i.op_str}'
        if i.mnemonic == 'bl' and i.op_str.startswith('#'):
            line += f'   ; -> {owner(int(i.op_str[1:], 16))}'
        if show:
            print(line)


# 1) full disassembly of rt_mutex_setprio (does it call adjust_prio_chain, and with which chwalk value)
dis('rt_mutex_setprio', 0x600)

# 2) whole-image search for callers of rt_mutex_adjust_prio_chain
apc = sym.get('rt_mutex_adjust_prio_chain')
print(f'\n=== callers of rt_mutex_adjust_prio_chain @{apc:#x}:')
# scan the whole text section for bl to apc
import struct
start = 0
n = len(data) // 4
found = []
for i in range(n):
    w = struct.unpack_from('<I', data, i * 4)[0]
    # BL: 1001 01xx xxxxxxxx xxxxxxxx xxxxxxxx  (imm26 signed)
    if (w >> 26) == 0x25:
        imm26 = w & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        tgt = vbase + i * 4 + imm26 * 4
        if tgt == apc:
            src = vbase + i * 4
            found.append(src)
for s in found:
    print(f'  caller: {owner(s)} @{s:#x}')
