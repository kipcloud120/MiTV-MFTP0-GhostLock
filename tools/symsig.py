#!/usr/bin/env python3
"""
symsig.py - locate the kallsyms address table in a raw arm64 kernel image using the "long monotonically increasing array" signature.

Rationale:
  * With CONFIG_KALLSYMS_BASE_RELATIVE=y the kernel holds kallsyms_offsets[]: num_syms
    u32 offsets sorted ascending by symbol address (relative to kallsyms_relative_base, a u64 right after the array).
    -> a very long strictly increasing u32 sequence is a strong signature for this table.
  * Absolute mode is num_syms ascending u64 values (kernel VA range).

Once located, align the symbol order from /proc/kallsyms (readable on device, addresses are 0) with the array entry by entry
to obtain "symbol name -> absolute address" without parsing the token table, without BTF and without a relocation table.

Usage:
  python symsig.py Image [--count N] [--base 0x...]
"""
import argparse
import gzip
import sys

import numpy as np


def load_image(path):
    data = open(path, "rb").read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def find_runs(mask, min_len):
    """return the True runs of mask with length >= min_len as [(start, end)]"""
    if not mask.any():
        return []
    idx = np.flatnonzero(np.diff(np.concatenate(([0], mask.view(np.int8), [0]))))
    out = []
    for s, e in zip(idx[0::2], idx[1::2]):
        if e - s >= min_len:
            out.append((int(s), int(e)))
    return out


def scan(data, count):
    n8 = len(data) // 8
    a8 = np.frombuffer(data[:n8 * 8], dtype="<u8")
    # absolute address table: kernel VA and ascending
    kern = (a8 >> 48) == 0xFFFF
    runs = find_runs(kern, count)
    results = []
    for s, e in runs:
        win = a8[s:s + count]
        if np.all(np.diff(win.astype(np.int64)) > 0):
            results.append(("absolute-u64", s * 8, int(win[0]), int(win[-1])))
    # relative offset table: ascending u32, plausible span (< 256MB)
    n4 = len(data) // 4
    a4 = np.frombuffer(data[:n4 * 4], dtype="<u4")
    # coarse filter: 64 consecutive increasing values
    d = np.diff(a4.astype(np.int64))
    inc = np.concatenate((d > 0, [False]))
    for s, e in find_runs(inc, max(64, count - 1)):
        if e - s < count - 1:
            continue
        win = a4[s:s + count]
        if win[0] > 0x1000:  # the offset table usually starts at 0 or a very small value
            continue
        if np.all(np.diff(win.astype(np.int64)) > 0) and int(win[-1]) < 0x1000_0000:
            rel_base = int.from_bytes(data[(s + count) * 4:(s + count) * 4 + 8], "little")
            if 0xffff000000000000 <= rel_base <= 0xffffffffffffffff:
                results.append(("relative-u32", s * 4, rel_base, rel_base + int(win[-1])))
            else:
                results.append(("relative-u32?", s * 4, rel_base, None))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--count", type=int, required=True, help="number of lines in /proc/kallsyms (total symbol count)")
    args = ap.parse_args()

    data = load_image(args.image)
    print(f"[+] image {len(data)} bytes, expected symbols {args.count}", file=sys.stderr)
    res = scan(data, args.count)
    if not res:
        print("[-] no candidate address table found", file=sys.stderr)
        return 1
    for kind, off, lo, hi in res[:8]:
        print(f"[+] {kind:14s} file_off=0x{off:x}  first={lo:#x}  last={hi if hi is None else hex(hi)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
