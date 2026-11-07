"""xref_page.py - scan the kernel .text for every adrp+ldr/str reference to a window inside one page
usage: python tools/xref_page.py <page> <lo> <hi>
e.g.   python tools/xref_page.py 0xffffff8009385000 0x580 0x5a0

Note: vmlinux.elf is merged into a single .kernel section with no separate .text,
so this does a fast full scan on the ADRP encoding first, then a local disassembly at each hit.
"""
import sys
import bisect
import struct
from elftools.elf.elffile import ELFFile
import capstone

page = int(sys.argv[1], 0)
lo = int(sys.argv[2], 0)
hi = int(sys.argv[3], 0)

elf = ELFFile(open('firmware/vmlinux.elf', 'rb'))
st = elf.get_section_by_name('.symtab')
funcs = []
names = {}
for s in st.iter_symbols():
    a = s['st_value']
    if a:
        names.setdefault(a, s.name)
        if s['st_info']['type'] == 'STT_FUNC':
            funcs.append(a)
funcs.sort()
faddr = funcs


def owner(a):
    i = bisect.bisect_right(faddr, a) - 1
    if i < 0:
        return '?'
    return '%s+%#x' % (names.get(faddr[i], '?'), a - faddr[i])


sec = elf.get_section_by_name('.kernel')
blob = sec.data()
base = sec['sh_addr']
end = base + len(blob)

# 1) fast ADRP scan for instructions whose page == page
hits_adrp = []
n = len(blob) // 4
words = struct.unpack('<%dI' % n, blob[:n * 4])
for i in range(n):
    w = words[i]
    if (w & 0x9F000000) != 0x90000000:
        continue
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    a = base + i * 4
    tgt = (a & ~0xFFF) + (imm << 12)
    if tgt == page:
        hits_adrp.append((a, (w & 0x1F)))

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False

rows = []
for a, rd in hits_adrp:
    off = a - base
    chunk = blob[off:off + 40]
    reg = 'x%d' % rd
    for k, ins in enumerate(md.disasm(chunk, a)):
        if k == 0:
            continue
        ops = ins.op_str
        if '[' not in ops or ins.mnemonic not in (
                'ldr', 'str', 'ldrb', 'strb', 'ldrh', 'strh', 'ldrsw',
                'ldrsh', 'add', 'sub', 'ldur', 'stur'):
            continue
        inner = ops[ops.index('[') + 1:ops.index(']')]
        parts = [p.strip() for p in inner.split(',')]
        if parts[0] != reg:
            continue
        imm = 0
        if len(parts) > 1:
            p = parts[1].lstrip('#')
            try:
                imm = int(p, 0)
            except Exception:
                continue
        if lo <= imm < hi:
            rows.append((a, ins.address, ins.mnemonic, ops, imm))

print('ADRP-to-page hits: %d' % len(hits_adrp))
print('accesses in window [%#x,%#x): %d' % (lo, hi, len(rows)))
for a_adrp, a, m, ops, imm in rows:
    print('  %#x  %-40s %-6s %-26s off=%#x' % (a, owner(a), m, ops, imm))
