"""nearby.py - print symbols near a target address and the section they belong to
usage: python tools/nearby.py 0xffffff8009385594 [n]
"""
import sys
import bisect
from elftools.elf.elffile import ELFFile

T = int(sys.argv[1], 0)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 8

elf = ELFFile(open('firmware/vmlinux.elf', 'rb'))
st = elf.get_section_by_name('.symtab')
rows = []
for s in st.iter_symbols():
    a = s['st_value']
    if a:
        rows.append((a, s['st_size'], s['st_info']['type'], s.name))
rows.sort()
addrs = [r[0] for r in rows]
i = bisect.bisect_left(addrs, T)
print('target %#x' % T)
for j in range(max(0, i - N), min(len(rows), i + N)):
    a, sz, t, n = rows[j]
    print('  %#x  sz=%#-8x %-12s %s%s' % (a, sz, t, n, '   <<<' if a == T else ''))

print('--- sections containing target ---')
for sec in elf.iter_sections():
    a, sz = sec['sh_addr'], sec['sh_size']
    if sz and a <= T < a + sz:
        print('  %-18s addr=%#x size=%#x off_in_sec=%#x' %
              (sec.name, a, sz, T - a))
