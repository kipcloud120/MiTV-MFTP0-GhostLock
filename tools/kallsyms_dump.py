#!/usr/bin/env python3
"""
kallsyms_dump.py - recover the symbol table from a raw arm64 kernel image (Image / Image.gz / vmlinux).

Supports:
  * CONFIG_KALLSYMS_BASE_RELATIVE=y  (kallsyms_offsets + kallsyms_relative_base)
  * absolute address mode (kallsyms_addresses)
Applies to: Linux 4.x - 6.x arm64 (no ELF, no BTF, no relocation table needed)

Usage:
  python kallsyms_dump.py Image [--grep pat] [--out syms.txt] [--json out.json]
"""
import argparse
import gzip
import json
import lzma
import re
import sys

import numpy as np


def load_image(path: str) -> bytes:
    data = open(path, "rb").read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
        print(f"[+] gunzip -> {len(data)} bytes", file=sys.stderr)
    elif data[:6] == b"\xfd7zXZ\x00":
        data = lzma.decompress(data)
        print(f"[+] unxz -> {len(data)} bytes", file=sys.stderr)
    elif data[:4] == b"\x02\x21\x4c\x18":
        try:
            import lz4.block  # type: ignore
            size = int.from_bytes(data[4:8], "little")
            data = lz4.block.decompress(data[12:], uncompressed_size=size)
            print(f"[+] unlz4 -> {len(data)} bytes", file=sys.stderr)
        except Exception as e:  # pragma: no cover
            print(f"[!] lz4 payload, install lz4: {e}", file=sys.stderr)
    return data


def find_token_index(data: bytes) -> list:
    """token_index immediately follows token_table: 256 u16 values, first element 0, non-decreasing."""
    arr = np.frombuffer(data, dtype="<u2")
    total = arr.size
    # require arr[i] == 0, arr[i..i+256] non-decreasing, last value < 4096
    zeros = np.flatnonzero(arr == 0)
    cands = []
    for i in zeros:
        if i + 256 > total:
            break
        win = arr[i:i + 256]
        if win[-1] > 8192:
            continue
        d = np.diff(win.astype(np.int32))
        if (d >= 0).all():
            cands.append(int(i) * 2)  # byte offset
    return cands


def read_cstr(data: bytes, off: int) -> bytes:
    end = data.find(b"\x00", off)
    if end < 0:
        return b""
    return data[off:end]


def validate_token_table(data: bytes, tok_idx_off: int):
    """before tok_idx_off there should be 256 NUL-terminated strings. Returns (table_start, tokens, total_len) or None."""
    # walk backwards from tok_idx_off over 256 NUL-terminated strings
    pos = tok_idx_off
    ends = []
    for _ in range(256):
        pos -= 1
        # skip a possible trailing NUL
        while pos > 0 and data[pos] == 0:
            pos -= 1
        end = pos + 1
        start = data.rfind(b"\x00", 0, end)
        if start < 0:
            return None
        if end - start - 1 > 200:  # token too long, not plausible
            return None
        ends.append((start + 1, end))
        pos = start
    ends.reverse()
    table_start = ends[0][0]
    tokens = [data[s:e] for s, e in ends]
    total_len = ends[-1][1] - table_start
    if not (200 < total_len < 4000):
        return None
    return table_start, tokens, total_len


def parse_names(data: bytes, names_start: int, n: int, markers_start: int, tokens):
    names = []
    pos = names_start
    for _ in range(n):
        if pos >= markers_start:
            return None
        ln = data[pos]
        pos += 1
        if ln & 0x80:  # long name (kernel >= 5.7)
            ln = (ln & 0x7F) | (data[pos] << 7)
            pos += 1
        if ln == 0 or ln > 127:
            return None
        if pos + ln > markers_start:
            return None
        idxs = data[pos:pos + ln]
        pos += ln
        name = b"".join(tokens[i] for i in idxs)
        names.append(name)
    if pos != markers_start:
        return None
    return names


def find_markers_start(data: bytes, tok_table_start: int, max_markers=4096):
    """markers is a u32 array, first element 0, non-decreasing, located immediately before token_table."""
    for k in range(1, max_markers):
        start = tok_table_start - 4 * k
        if start < 0:
            break
        win = np.frombuffer(data[start:tok_table_start], dtype="<u4")
        if win.size != k or win[0] != 0:
            continue
        d = np.diff(win.astype(np.int64))
        if (d > 0).all():
            return start, k
    return None, 0


def build_symbols(data: bytes):
    tok_cands = find_token_index(data)
    print(f"[+] token_index candidates: {len(tok_cands)}", file=sys.stderr)
    for tok_idx_off in tok_cands[:400]:
        vt = validate_token_table(data, tok_idx_off)
        if not vt:
            continue
        table_start, tokens, _ = vt
        markers_start, nk = find_markers_start(data, table_start)
        if markers_start is None:
            continue
        n_lo, n_hi = 256 * (nk - 1) + 1, 256 * nk
        # find the start of names before markers: 4 bytes before it == num_syms, the 12 before that are relative_base
        search_from = max(0, markers_start - 4_000_000)
        for p in range(markers_start - 8, search_from, -1):
            if p - 12 < 0:
                break
            num = int.from_bytes(data[p - 4:p], "little")
            if not (n_lo <= num <= n_hi):
                continue
            rel_base = int.from_bytes(data[p - 12:p - 4], "little")
            if not (0xffff000000000000 <= rel_base <= 0xffffffffffffffff):
                continue
            names = parse_names(data, p, num, markers_start, tokens)
            if names is None:
                continue
            # address table: BASE_RELATIVE -> num s32; otherwise num u64
            off32 = p - 12 - 4 * num
            addr64 = p - 12 - 8 * num
            if off32 > 0:
                raw = np.frombuffer(data[off32:off32 + 4 * num], dtype="<i4")
                addrs = [rel_base + int(v) for v in raw]
                if all(a >= rel_base for a in addrs[:64]):
                    return names, addrs, rel_base, "base-relative"
            if addr64 > 0:
                raw = np.frombuffer(data[addr64:addr64 + 8 * num], dtype="<u8")
                addrs = [int(v) for v in raw]
                if sum(1 for a in addrs[:64] if a >= 0xffff000000000000) > 32:
                    return names, addrs, 0, "absolute"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--grep", default=None, help="only print symbols whose name matches this regex")
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    data = load_image(args.image)
    print(f"[+] image size {len(data)} bytes (0x{len(data):x})", file=sys.stderr)
    res = build_symbols(data)
    if not res:
        print("[-] kallsyms tables not found", file=sys.stderr)
        return 1
    names, addrs, rel_base, mode = res
    print(f"[+] mode={mode} symbols={len(names)} relative_base={rel_base:#x}", file=sys.stderr)

    pairs = [(addrs[i], names[i].decode("latin1")) for i in range(len(names))]
    text = [a for a, n in pairs if n == "_text"] or [min(addrs)]
    base = text[0]
    print(f"[+] kernel base (_text) = {base:#x}", file=sys.stderr)

    out = []
    pat = re.compile(args.grep) if args.grep else None
    for a, n in pairs:
        line = f"{a:016x} {n}"
        if pat and not pat.search(n):
            continue
        out.append(line)
    if args.grep:
        for line in out[:60]:
            print(line)
        if len(out) > 60:
            print(f"... ({len(out)} matched)")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(f"[+] wrote {args.out} ({len(out)} lines)", file=sys.stderr)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({n: a for a, n in pairs}, f)
        print(f"[+] wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
