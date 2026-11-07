"""dis_so.py - disassemble a named function inside preload_*.so
usage: python dis_so.py <so path> <function name> [span]
"""
import sys
import capstone
from elftools.elf.elffile import ELFFile

path = sys.argv[1]
name = sys.argv[2]
span = int(sys.argv[3], 0) if len(sys.argv) > 3 else None

elf = ELFFile(open(path, 'rb'))
st = elf.get_section_by_name('.symtab')
sym = {}
for s in st.iter_symbols():
    if s.name and s['st_value']:
        sym.setdefault(s.name, (s['st_value'], s['st_size']))
addr2name = {}
for n, (a, sz) in sym.items():
    addr2name.setdefault(a, n)

text = elf.get_section_by_name('.text')
taddr, tdata = text['sh_addr'], text.data()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

a, sz = sym.get(name, (None, None))
if a is None:
    print(f'--- {name}: MISSING'); sys.exit(1)
if span:
    sz = span
ins = list(md.disasm(tdata[a - taddr:a - taddr + sz], a))
print(f'=== {name} @{a:#x} size={sz:#x}')
for i in ins:
    line = f'  +{i.address-a:#06x} {i.mnemonic} {i.op_str}'
    if i.mnemonic == 'bl' and i.op_str.startswith('#'):
        tgt = int(i.op_str[1:], 16)
        line += f'   ; -> {addr2name.get(tgt, "?")}'
    if i.mnemonic.startswith('adrp') or 'adr ' in i.mnemonic:
        pass
    print(line)
