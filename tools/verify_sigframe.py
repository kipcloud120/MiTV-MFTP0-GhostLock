"""verify_sigframe.py - offline re-verification of two things:
1. the frame pointer computation in compat_restore_sigframe -> compat_restore_vfp_context
   (confirm frame = uc + 0xE8, i.e. whether the handler source offset uc+0xF0+8j holds)
2. the size check in sched_copy_attr (does the nudge sched_attr size trigger EINVAL)
"""
import sys
import struct
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
        mid = (lo + hi) // 2
        if sorted_addrs[mid] <= addr:
            best, lo = sorted_addrs[mid], mid + 1
        else:
            hi = mid - 1
    return addr2name.get(best, '?')


def fsize(a):
    idx = sorted_addrs.index(a)
    if idx + 1 < len(sorted_addrs):
        return min(0x800, sorted_addrs[idx + 1] - a)
    return 0x800


def dis(name, show=True):
    a = sym.get(name)
    if not a:
        print(f'--- {name}: MISSING')
        return None
    sz = fsize(a)
    print(f'=== {name} @{a:#x} size={sz:#x}')
    for i in md.disasm(data[a - vbase:a - vbase + sz], a):
        line = f'  +{i.address-a:#06x} {i.mnemonic} {i.op_str}'
        if i.mnemonic == 'bl' and i.op_str.startswith('#'):
            t = owner(int(i.op_str[1:], 16))
            if t not in NOISE:
                line += f'   ; -> {t}'
        if show:
            print(line)
    return a


# ---- 0) symbol scan ----
print('### relevant symbols:')
for n in sorted(sym):
    ln = n.lower()
    if any(k in ln for k in ('vfp', 'sigframe', 'sigreturn', 'sched_copy_attr',
                             'sched_setattr')):
        print(f'  {sym[n]:#x} {n}')

# ---- 1) sigreturn -> vfp frame pointer ----
print('\n### 1) compat_restore_sigframe -> compat_restore_vfp_context')
vfp = sym.get('compat_restore_vfp_context')
print(f'  compat_restore_vfp_context = {vfp:#x}' if vfp else '  vfp: MISSING')
for nm in ('compat_restore_sigframe', 'compat_sys_rt_sigreturn'):
    dis(nm)

# whole-image scan for callers of bl -> vfp
if vfp:
    n = len(data) // 4
    print(f'### whole-image callers of bl -> compat_restore_vfp_context @{vfp:#x}:')
    for i in range(n):
        w = struct.unpack_from('<I', data, i * 4)[0]
        if (w >> 26) == 0x25:
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            if vbase + i * 4 + imm * 4 == vfp:
                s = vbase + i * 4
                print(f'  {owner(s)} @{s:#x} (+{s - owner_addr if False else 0})')

# ---- 2) sched_copy_attr size check ----
print('\n### 2) sched_copy_attr / sched_setattr size check')
for nm in ('sched_copy_attr', '__se_sys_sched_setattr', 'sys_sched_setattr',
           'compat_sys_sched_setattr'):
    dis(nm)
