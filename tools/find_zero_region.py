"""find_zero_region.py - find a zero-filled region in vmlinux.elf that is safe to use as a fake rt_mutex
Criteria: 1) inside a writable segment 2) >=0x40 bytes of zeros 3) no symbol inside the region (+-0x40)
      4) no adrp+add reference to that address anywhere in the image (+-0x30)
"""
import struct
import capstone
from elftools.elf.elffile import ELFFile

elf = ELFFile(open('firmware/vmlinux.elf', 'rb'))
st = elf.get_section_by_name('.symtab')
syms = [(s['st_value'], s['st_size'], s.name) for s in st.iter_symbols() if s.name and s['st_value']]
syms.sort()
sym_addrs = [a for a, _, _ in syms]

writable = []
for sp in elf.iter_segments():
    if sp['p_type'] == 'PT_LOAD' and (sp['p_flags'] & 2):
        writable.append(sp)
print('writable segments:', [(hex(s['p_vaddr']), hex(s['p_filesz']), s['p_flags']) for s in writable])

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
# collect every adrp+add result (data reference)
refs = set()
for sp in elf.iter_segments():
    if sp['p_type'] != 'PT_LOAD':
        continue
    data, base = sp.data(), sp['p_vaddr']
    adrp = {}
    for i in md.disasm(data, base):
        if i.mnemonic == 'adrp':
            try:
                r, v = i.op_str.split(', #')
                adrp[r] = int(v, 16)
            except ValueError:
                pass
        elif i.mnemonic == 'add' and '#' in i.op_str:
            parts = i.op_str.replace(',', ' ').split()
            if len(parts) == 3 and parts[1] in adrp:
                try:
                    refs.add(adrp[parts[1]] + int(parts[2].replace('#', ''), 16))
                except ValueError:
                    pass
print('data reference points:', len(refs))

cands = []
for sp in writable:
    data, base = sp.data(), sp['p_vaddr']
    n = len(data)
    i = 0
    while i < n - 0x40:
        if data[i] == 0:
            j = i
            while j < n and data[j] == 0:
                j += 1
            if j - i >= 0x40:
                va = base + i
                # no symbol cover (within +-0x40)
                if not any(va - 0x40 <= a <= va + 0x40 for a in sym_addrs):
                    # no code reference
                    hit = sum(1 for r in refs if va <= r < va + 0x40)
                    if hit == 0:
                        cands.append((va, j - i))
            i = j
        else:
            i += 1

print(f'{len(cands)} candidates, first 15:')
for va, ln in cands[:15]:
    print(f'  {va:#x}  len={ln:#x}')
