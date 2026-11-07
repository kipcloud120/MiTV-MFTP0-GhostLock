#!/usr/bin/env python3
"""
fetch_ota.py - fetch the full OTA package through the Xiaomi TV upgrade API, and optionally range-download a single file from it.

Key point: the API accepts a packagetype=full parameter that the opaque signature does not cover.
       Take a getupgradeinfo URL captured from the TV logcat, append &packagetype=full, and
       you get packageurl / packageurl2 (a full zip with boot.img, vbmeta.img, system, ...).

Usage:
  # 1) capture a signed URL on the TV first
  #    adb shell "logcat -d | grep -o 'http://upgrade.ptmi.gitv.tv/tvservice/getupgradeinfo[^\"]*' | tail -1"
  # 2) then use this script
  python fetch_ota.py --url "<captured URL>" --info
  python fetch_ota.py --url "<captured URL>" --list
  python fetch_ota.py --url "<captured URL>" --extract boot.img -o boot.img

Notes:
  * ts/nonce/opaque in the URL expire; capture a fresh URL when that happens
  * the package is ~1.3 GB; --extract uses a Range request and never downloads the whole zip
"""
import argparse
import json
import struct
import sys
import urllib.request
import zlib


def http_get(url, headers=None, timeout=60):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), dict(r.headers)


def ranged(url, start, end, timeout=120):
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def api_info(base_url):
    sep = "&" if "?" in base_url else "?"
    url = base_url if "packagetype=" in base_url else base_url + sep + "packagetype=full"
    body, _ = http_get(url, {"User-Agent": "okhttp/3.12.0"})
    data = json.loads(body)
    if data.get("status") != 0:
        print(f"[!] API status={data.get('status')}(the signature may have expired, capture a new URL from logcat)", file=sys.stderr)
        return None
    return data.get("data", {})


def parse_cd(cd):
    p = 0
    while cd[p:p + 4] == b"PK\x01\x02":
        f = struct.unpack("<HHHHHHIIIHHHHHII", cd[p + 4:p + 46])
        method, csize, usize = f[3], f[7], f[8]
        nlen, elen, clen, lho = f[9], f[10], f[11], f[15]
        name = cd[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        yield {"name": name, "method": method, "csize": csize,
               "usize": usize, "lho": lho, "nlen": nlen}
        p += 46 + nlen + elen + clen


def read_cd(url, total):
    tail = 4 * 1024 * 1024
    tail = min(tail, total)
    buf = ranged(url, total - tail, total - 1)
    i = buf.rfind(b"PK\x05\x06")
    if i < 0:
        raise RuntimeError("EOCD not found")
    _, _, _, _, _, cd_size, cd_off = struct.unpack("<IHHHHII", buf[i:i + 22])
    if cd_off >= total - tail:
        return buf[cd_off - (total - tail): cd_off - (total - tail) + cd_size]
    return ranged(url, cd_off, cd_off + cd_size - 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="getupgradeinfo URL captured from the TV logcat")
    ap.add_argument("--info", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", default=None, help="file name inside the zip to extract, e.g. boot.img")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--pkg-url", default=None, help="specify the package URL directly (skips the API)")
    args = ap.parse_args()

    if args.pkg_url:
        pkg = args.pkg_url
        total = None
    else:
        d = api_info(args.url)
        if not d:
            return 1
        pkg = d.get("packageurl") or d.get("packageurl2")
        total = d.get("packagesize")
        if args.info or not (args.list or args.extract):
            print(json.dumps({k: d.get(k) for k in
                              ["availableversion", "packagetype", "packagesize",
                               "packageurl", "packageurl2", "canupgrade"]},
                             ensure_ascii=False, indent=2))
        if not (args.list or args.extract):
            return 0
        if not pkg:
            print("[!] the response has no packageurl / packageurl2", file=sys.stderr)
            return 1

    print(f"[+] package: {pkg}", file=sys.stderr)
    if total is None:
        _, hdrs = http_get(pkg, {"Range": "bytes=0-0"})
        cr = hdrs.get("Content-Range", "")
        total = int(cr.split("/")[-1]) if "/" in cr else int(hdrs.get("Content-Length", 0))
    print(f"[+] size: {total}", file=sys.stderr)

    cd = read_cd(pkg, total)
    entries = list(parse_cd(cd))
    if args.list or not args.extract:
        print(f"{'name':45s} {'method':>6s} {'csize':>12s} {'usize':>12s}")
        for e in entries:
            print(f"{e['name']:45s} {e['method']:6d} {e['csize']:12d} {e['usize']:12d}")

    if args.extract:
        target = next((e for e in entries if e["name"] == args.extract), None)
        if not target:
            print(f"[!] {args.extract} is not in the package", file=sys.stderr)
            return 1
        hdr = ranged(pkg, target["lho"], target["lho"] + 29)
        if hdr[:4] != b"PK\x03\x04":
            raise RuntimeError("bad local header")
        lnlen, lelen = struct.unpack("<HH", hdr[26:30])
        data_start = target["lho"] + 30 + lnlen + lelen
        print(f"[+] range fetch {target['csize']} bytes @ 0x{data_start:x}", file=sys.stderr)
        blob = ranged(pkg, data_start, data_start + target["csize"] - 1)
        raw = zlib.decompressobj(-15).decompress(blob) if target["method"] == 8 else blob
        out = args.out or args.extract
        open(out, "wb").write(raw)
        print(f"[+] wrote {out} ({len(raw)} bytes, expected {target['usize']})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
