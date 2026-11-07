"""find_waiter.py - locate the stack base of rt_waiter inside futex_wait_requeue_pi
Idea: track registers holding x29-relative add/sub results and look for the self-referential store "x29+imm into [x29+imm2]"
     (RB_CLEAR_NODE is exactly node->__rb_parent_color = node)
"""
import sys, struct, re
import capstone
from elftools.elf.elffile import ELFFile

ELF = 'firmware/vmlinux.elf'
elf = ELFFile(open(ELF, 'rb'))
st = elf.get_section_by_name('.symtab')
sym = {}
for s in st.iter_symbols():
    if s.name and s['st_value']:
        sym.setdefault(s.name, s['st_value'])

seg = max([sp for sp in elf.iter_segments() if sp['p_type'] == 'PT_LOAD'],
          key=lambda s: s['p_filesz'])
data, vbase = seg.data(), seg['p_vaddr']
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

FUNC = sys.argv[1] if len(sys.argv) > 1 else 'futex_wait_requeue_pi.constprop.19'
SPAN = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x600

a = sym.get(FUNC)
if a is None:
    cands = [k for k in sym if FUNC.split('.')[0] in k]
    print('missing', FUNC, 'candidates:', cands)
    sys.exit(1)

ins = list(md.disasm(data[a - vbase:a - vbase + SPAN], a))

# ---- abstract interpretation: register -> x29 offset ----
val = {}          # reg -> ('fp', off) or ('const', n)
def clear():
    val.clear()
    val['x29'] = ('fp', 0)

lbl = {}          # print context for each str

print(f'=== {FUNC} @{a:#x}  (first {SPAN:#x} bytes, {len(ins)} instructions)')
print('--- all sp/fp-relative stores (str/stp) + xN definitions ---')
for i in ins:
    off = i.address - a
    t = f'+{off:#06x} {i.mnemonic:8s} {i.op_str}'
    m = i.mnemonic
    ops = i.op_str

    # 1) record add/sub xN, x29, #imm
    mm = re.match(r'^(x\d+),\s*x29,\s*#(0x[0-9a-f]+|\d+)$', ops)
    if m in ('add', 'sub'):
        mm2 = re.match(r'^(x\d+),\s*x29,\s*#(0x[0-9a-f]+|\d+)$', ops)
        if mm2:
            r, k = mm2.group(1), int(mm2.group(2), 0)
            val[r] = ('fp', k if m == 'add' else -k)
            print(f'{t:40s}   ; {r} = x29{m}{k:#x}')
            continue
    # mov xN, xM / mov xN, sp
    mm3 = re.match(r'^(x\d+),\s*(sp|x29)$', ops)
    if m == 'mov' and mm3:
        val[mm3.group(1)] = ('fp', 0)
        print(f'{t:40s}   ; {mm3.group(1)} = fp')
        continue
    mm4 = re.match(r'^(x\d+),\s*(x\d+)$', ops)
    if m == 'mov' and mm4:
        if mm4.group(2) in val:
            val[mm4.group(1)] = val[mm4.group(2)]
        print(f'{t:40s}   ; {mm4.group(1)} = {mm4.group(2)}')
        continue

    # 2) str xS, [x29, #imm]   self-reference check
    mm5 = re.match(r'^(x\d+|w\d+),\s*\[(sp|x29|x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]$', ops)
    if m in ('str', 'strb', 'strh', 'stp') and '[' in ops:
        pass
    if m == 'str':
        mm6 = re.match(r'^(x\d+),\s*\[(x29|sp|x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]$', ops)
        if mm6:
            src, base = mm6.group(1), mm6.group(2)
            d = int(mm6.group(3), 0) if mm6.group(3) else 0
            b = val.get(base)
            s = val.get(src)
            mark = ''
            if b and b[0] == 'fp' and s and s[0] == 'fp':
                if b[1] + d == s[1]:
                    mark = '   <<<< SELF (RB_CLEAR_NODE)'
            if b and b[0] == 'fp':
                print(f'{t:40s}   ; [x29{d-0 if d==0 else ""}{"" if d==0 else f"{d:+#x}"}] <- {src}{"" if not s else f"=x29{s[1]:+#x}"}{mark}')
            continue

    # 3) any other instruction that clobbers a known register clears it
    if m in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'adrp', 'adr') and ',' in ops:
        r0 = ops.split(',')[0].strip()
        val.pop(r0, None)

print()
print('--- self-referential stores only ---')
val.clear(); val['x29'] = ('fp', 0)
for i in ins:
    off = i.address - a
    if i.mnemonic in ('add', 'sub'):
        mm2 = re.match(r'^(x\d+),\s*x29,\s*#(0x[0-9a-f]+|\d+)$', i.op_str)
        if mm2:
            val[mm2.group(1)] = ('fp', int(mm2.group(2), 0) * (1 if i.mnemonic == 'add' else -1))
        continue
    if i.mnemonic == 'mov':
        mm4 = re.match(r'^(x\d+),\s*(x\d+|sp|x29)$', i.op_str)
        if mm4:
            if mm4.group(2) in ('sp', 'x29'):
                val[mm4.group(1)] = ('fp', 0)
            elif mm4.group(2) in val:
                val[mm4.group(1)] = val[mm4.group(2)]
        continue
    if i.mnemonic == 'str':
        mm6 = re.match(r'^(x\d+),\s*\[(x29|sp|x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]$', i.op_str)
        if mm6:
            src, base = mm6.group(1), mm6.group(2)
            d = int(mm6.group(3), 0) if mm6.group(3) else 0
            b, s = val.get(base), val.get(src)
            if b and b[0] == 'fp' and s and s[0] == 'fp':
                lo = b[1] + d
                if lo == s[1]:
                    print(f'  +{off:#06x} str {src},[{base},#{d:#x}]   ->  [S{b[1]:+#x}] = &[S{s[1]:+#x}]   *** SELF ***')
    if i.mnemonic.startswith('ldr') and ',' in i.op_str:
        val.pop(i.op_str.split(',')[0].strip(), None)
