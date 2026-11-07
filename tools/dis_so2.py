"""dis_so2.py - disassemble a .so and resolve PLT/veneer jump targets
usage: python dis_so2.py <so> <function name> [span]
"""
import sys
import capstone
from elftools.elf.elffile import ELFFile

path, name = sys.argv[1], sys.argv[2]
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

# rela.plt: r_offset = GOT slot, symbol = imported name; PLT slots map by index
relplt = elf.get_section_by_name('.rela.plt')
dynsym = elf.get_section_by_name('.dynsym')
got2imp = {}
for i, r in enumerate(relplt.iter_relocations()):
    si = r['r_info_sym']
    nm = dynsym.get_symbol(si).name
    got2imp[r['r_offset']] = nm

plt = elf.get_section_by_name('.plt')
plt_addr, plt_data = plt['sh_addr'], plt.data()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def resolve(addr):
    """resolve an address: symbol name or PLT slot -> imported function name"""
    if addr in addr2name:
        return addr2name[addr]
    if plt_addr <= addr < plt_addr + plt['sh_size']:
        off = addr - plt_addr
        ins = list(md.disasm(plt_data[off:off + 0x20], addr))
        # adrp xN, got_page; ldr xN, [xN, off]; br xN  → got slot
        for i in ins:
            if i.mnemonic == 'ldr':
                # ldr x17, [x16, #imm]
                op = i.op_str
                imm = int(op.split('#')[1].rstrip(']'), 16) if '#' in op else 0
                # look back for the adrp page
                for j in ins:
                    if j.mnemonic == 'adrp':
                        page = int(j.op_str.split('#')[1], 16)
                        got = (page & ~0xfff) + imm
                        if got in got2imp:
                            return f'PLT:{got2imp[got]}'
        return 'PLT:?'
    # veneer: b to the symbol
    off = addr
    # disassemble the first instruction of the veneer
    data = None
    for sec in elf.iter_sections():
        if sec['sh_type'] == 'SHT_PROGBITS' and sec['sh_addr'] <= addr < sec['sh_addr'] + sec['sh_size']:
            data = sec.data()[addr - sec['sh_addr']:addr - sec['sh_addr'] + 8]
            break
    if data:
        vi = list(md.disasm(data, addr))
        if vi and vi[0].mnemonic == 'b':
            tgt = int(vi[0].op_str[1:], 16)
            if tgt in addr2name:
                return addr2name[tgt] + ' (veneer)'
            r = resolve(tgt) if tgt != addr else None
            if r:
                return r
    return '?'

text = elf.get_section_by_name('.text')
taddr, tdata = text['sh_addr'], text.data()

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
        line += f'   ; -> {resolve(int(i.op_str[1:], 16))}'
    print(line)
