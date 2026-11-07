# MiTV-MFTP0 GhostLock

Port of the **GhostLock** futex priority-inheritance use-after-free local privilege
escalation (CVE-2026-43499) to the **Xiaomi MiTV-MFTP0** television, plus a full
teardown of the vendor's unauthenticated root command channel.

The target runs Android 9 on a MediaTek MT9652 with a 32-bit armv8l userspace and
Linux 4.9.118. The published GhostLock exploit targets arm64 5.x devices; getting it
to work here required re-deriving the stack geometry from `vmlinux.elf`, discovering
that arm64 4.9 has no separate IRQ stack (which silently destroys the heap/stack
spray between two syscalls), and building two instruments — a VFP register echo and
an offset scanner — to find out where the copy actually lands.

**Result:** a working write-NULL primitive that flips `selinux_enforcing` to 0 from an
unprivileged process. Arbitrary write of non-zero data was not achieved.

| | |
|---|---|
| Target | Xiaomi MiTV-MFTP0 / `alita` / L65R8-X |
| Build | `23.2.10.6129` · Android 9 · `PPR2.180905.006.A1` · user/release-keys |
| SoC | MediaTek MT9652 (platform `m7642`), armv8l, 2.6 GB RAM |
| Kernel | Linux 4.9.118+ (MStar GCC 4.9.2, built 2023-02-10) |
| Boot | AVB green, dm-verity enforcing, `vbmeta` = SHA256_RSA2048 |
| Storage | 29.8 GB eMMC, MStar private partition table (not GPT), 37 entries |
| Bug | `futex_wait_requeue_pi` leaves `task->pi_blocked_on` dangling on the ETIMEDOUT path |
| Primitive | write 8 zero bytes to an arbitrary physmap address |
| Success rate | ~1/3 per attempt; ~2/3 silent no-op; ~1/5 watchdog reset |

## What is in here

```
ghost/       the exploit, the on-device helper scripts and the dump harness
tools/       15 offline analysis scripts (kallsyms recovery, disassembly, frame surveys)
cve2215/     reference kernel sources for 4.9 (futex / rtmutex / binder / socket)
```

Not included, on purpose:

* **Partition images** (5.7 GB) — copyrighted firmware, and some of them may contain
  per-device key material. `ghost/dumpset.sh`, `ghost/dumpraw.sh` and
  `ghost/gen_manifest.py` reproduce and verify the whole set.
* **The OTA package** (1.3 GB) — same reason.
* **Compiled binaries** — build them, see below.

## Build

```bash
# exploit (static, 32-bit ARM). Note: zig build-exe rejects -O2/-Wall; use zig cc.
zig cc -target arm-linux-musleabihf -static -O2 -Wall \
    -o ghost/ghost24 ghost/ghost24.c

# persistence payload (frozen experiment, see WRITEUP.md section 12)
zig build-lib -target arm-linux-musleabihf -O ReleaseSmall -dynamic \
    -lc ghost/ghostboot.c -femit-bin=ghost/libmiffmpeg.so
```

## Run

```bash
export DEV=<tv-ip>:5555          # network adb must already be enabled by hand
export ADB=adb                   # or a full path to adb

# 1. zero-risk self-proof: does the write primitive land at all?
bash ghost/run24b.sh --walk --soft --ucoff 0x108 121 19 --rounds 4000

# 2. real run: flip selinux_enforcing, retrying across processes
bash ghost/off_selinux.sh

# 3. measure the outcome distribution without hitting the target
bash ghost/nullscan.sh 6

# 4. from here on, one command at a time as root
bash ghost/r.sh 'id'

# 5. keep a copy of dmesg on /data for the next lockup (pstore is empty on this TV)
bash ghost/klogd_ctl.sh start
```

`off_selinux.sh` starts the root agent over `TvService` transaction 4400 as soon as it
runs. That channel is reachable from plain adb shell even with SELinux enforcing
(measured on a cold boot) — so the exploit is not a prerequisite for root, and the
root agent is what supplies the physical page the exploit needs. See `WRITEUP.md`
section 11.

## Documentation

* **[WRITEUP.md](WRITEUP.md)** — the full technical write-up: kernel configuration,
  the bug, the re-derived stack geometry, the `--soft` recipe, measured outcome
  distribution, the `TvService` backdoor, the SELinux boundary matrix, the frozen
  persistence chain, and the partition-table findings.
* **[ghost/ghost24.c](ghost/ghost24.c)** — the exploit, with the version-by-version
  reasoning inline. Start at the top of the file.

## Credits

* GhostLock / CVE-2019-2215 lineage: the original Bad Binder write-up by Jann Horn,
  and the `GhostLock-for-OnePlus` port that this work started from.
* `cve2215/` contains Linux 4.9 kernel sources (GPL-2.0), kept only as a reference
  for the exact code paths; see `LICENSE`.
