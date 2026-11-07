"""stacksurvey.py - global survey: find every function that copies from user space into a stack buffer,
compute the cumulative frame depth from the syscall entry to the buffer and compare it with the target depth.
Goal: cover [T0, T0+0x38) = the fake waiter's pi_tree_entry..deadline fields
  - 64-bit: waiter = S-0x288 -> need to cover [S-0x270, S-0x238)
  - 32-bit: waiter = S-0x278 -> need to cover [S-0x260, S-0x228)
usage: python stacksurvey.py [target=0x270]
"""
import re
import sys
import capstone
from elftools.elf.elffile import ELFFile

TARGET = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x270
elf = ELFFile(open('firmware/vmlinux.elf', 'rb'))
st = elf.get_section_by_name('.symtab')
sym = {}
for s in st.iter_symbols():
    if s.name and s['st_value']:
        sym.setdefault(s.name, s['st_value'])
addr2name = {}
for n, a in sym.items():
    addr2name.setdefault(a, n)
funcs = sorted(addr2name)
seg = max([sp for sp in elf.iter_segments() if sp['p_type'] == 'PT_LOAD'],
          key=lambda s: s['p_filesz'])
data, vbase = seg.data(), seg['p_vaddr']
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
COPY = ('__arch_copy_from_user', '__copy_from_user', 'copy_from_user',
        'copy_msghdr_from_user', 'move_addr_to_kernel', '_copy_from_user')

info = {}   # func -> dict(frame, calls=[], bufs=[(imm,size_hint)])
func_index = {a: i for i, a in enumerate(funcs)}


def next_func(addr):
    lo, hi = 0, len(funcs) - 1
    res = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid] > addr:
            res, hi = funcs[mid], mid - 1
        else:
            lo = mid + 1
    return res or (vbase + len(data))


print('# scanning functions...')
for idx, a in enumerate(funcs):
    if not (vbase <= a < vbase + len(data)):
        continue
    end = min(next_func(a), a + 0x4000, vbase + len(data))
    name = addr2name[a]
    try:
        ins = list(md.disasm(data[a - vbase:end - vbase], a))
    except Exception:
        continue
    if not ins:
        continue
    fr = 0
    f0 = ins[0]
    if f0.mnemonic == 'stp' and f0.op_str.startswith('x29, x30, [sp, #-'):
        try:
            fr = int(f0.op_str.split('#-')[1].rstrip(']!'), 16)
        except ValueError:
            fr = 0
    elif f0.mnemonic == 'sub' and f0.op_str.startswith('sp, sp, #'):
        try:
            fr = int(f0.op_str.split('#')[1].rstrip(']'), 16)
        except ValueError:
            fr = 0
    calls, bufs = [], []
    for j, i in enumerate(ins):
        if i.mnemonic == 'bl' and i.op_str.startswith('#'):
            t = int(i.op_str[1:], 16)
            nm = addr2name.get(t)
            if nm:
                calls.append(nm)
                if nm in COPY:
                    # look back up to 4 instructions for add x?, x29/sp, #imm as the copy destination
                    sz = 0
                    for m in range(j - 1, max(j - 9, -1), -1):
                        q = ins[m]
                        if q.mnemonic in ('mov', 'orr') and (q.op_str.split(',')[0] in ('w2', 'x2')):
                            mm = re.search(r'#(0x[0-9a-f]+|\d+)', q.op_str)
                            if mm:
                                v = mm.group(1)
                                sz = int(v, 16) if v.startswith('0x') else int(v)
                            break
                    for k in range(j - 1, max(j - 9, -1), -1):
                        q = ins[k]
                        if q.mnemonic == 'add' and ('x29, #' in q.op_str or ' sp, #' in q.op_str):
                            try:
                                imm = int(q.op_str.split('#')[1].rstrip(']'), 16)
                            except ValueError:
                                continue
                            bufs.append((imm, sz))
                            break
    info[name] = dict(frame=fr, calls=calls, bufs=bufs)

entries = [n for n in info if n.startswith(('sys_', 'compat_sys_', 'SyS_'))]
print(f'# functions {len(info)}, entries {len(entries)}, target cover {TARGET:#x}')


def walk(name, depth, acc, seen):
    """DFS to compute the minimum cumulative frame depth of each function"""
    if depth > 6 or name in seen:
        return
    seen = seen | {name}
    node = info.get(name)
    if not node:
        return
    base = acc + node['frame']
    best = BEST.get(name)
    if best is None or base < best:
        BEST[name] = base
    for c in node['calls']:
        if c in info:
            walk(c, depth + 1, base, seen)


BEST = {}
for e in entries:
    walk(e, 0, 0, frozenset())

print('# candidates with a stack buffer whose depth is close to the target:')
rows = []
for name, node in info.items():
    if not node['bufs'] or name not in BEST:
        continue
    for imm, sz in node['bufs']:
        d = BEST[name] - imm
        cover = d + sz if sz else d
        ok = d <= TARGET <= cover if sz else abs(d - TARGET) <= 0x10
        rows.append((abs(d - TARGET), d, name, imm, sz, BEST[name], ok))
rows.sort()
for a_, d, name, imm, sz, best, ok in rows[:25]:
    print(f'  depth={d:#06x} size={sz:#06x} best={best:#06x} {name} buf@{imm:#x} '
          f'{"COVER" if ok else ""}')
