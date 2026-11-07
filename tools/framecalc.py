"""framecalc.py - compact frame-depth survey: frame size + effective calls + stack-buffer candidates (x29/sp-relative add)
usage: python framecalc.py sym...
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
NOISE = ('_mcount', '__stack_chk_fail', '__memset', 'memcpy', 'find_next_bit')


def owner(addr):
    lo, hi, best = 0, len(sorted_addrs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if sorted_addrs[mid] <= addr:
            best, lo = sorted_addrs[mid], mid + 1
        else:
            hi = mid - 1
    return addr2name.get(best, '?')


def scan(name, span=0x600):
    a = sym.get(name)
    if not a:
        print(f'--- {name}: MISSING')
        return
    ins = list(md.disasm(data[a - vbase:a - vbase + span], a))
    if not ins:
        print(f'--- {name}: no disasm')
        return
    fr = 0
    f0 = ins[0]
    if f0.mnemonic == 'stp' and f0.op_str.startswith('x29, x30, [sp, #-'):
        fr = int(f0.op_str.split('#-')[1].rstrip(']!'), 16)
    elif f0.mnemonic == 'sub' and f0.op_str.startswith('sp, sp, #'):
        fr = int(f0.op_str.split('#')[1], 16)
    print(f'--- {name} @{a:#x} frame={fr:#x}')
    buf = []
    for idx, i in enumerate(ins):
        if i.mnemonic == 'bl' and i.op_str.startswith('#'):
            nm = owner(int(i.op_str[1:], 16))
            if nm != name and not any(k in nm for k in NOISE):
                print(f'   +{i.address-a:#06x} bl {nm}')
        if i.mnemonic in ('add', 'addg') and ('x29, #' in i.op_str or 'sp, #' in i.op_str):
            try:
                imm = int(i.op_str.split('#')[1].rstrip(']'), 16)
            except ValueError:
                continue
            if imm < max(fr, 0x400):
                nxt = ' | '.join(f'{ins[j].mnemonic} {ins[j].op_str}' for j in range(idx + 1, min(idx + 3, len(ins))))
                buf.append((imm, i.address - a, i.op_str, nxt))
    for imm, off, txt, nxt in buf:
        print(f'   buf? +{off:#06x} {txt}  -> {nxt}')


for n in sys.argv[1:]:
    scan(n)
