#!/usr/bin/env python3
"""kstream.py - host-side listener that receives real-time kernel log lines
pushed from the device (dmesg -w).

Usage:  python ghost/kstream.py <port> <outfile> [seconds]
Device side, via the root channel:  dmesg -w | netcat 127.0.0.1 <port>
Pair with:  adb reverse tcp:<port> tcp:<port>
"""
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777
out = sys.argv[2] if len(sys.argv) > 2 else "ghost/kpanic.txt"
dur = float(sys.argv[3]) if len(sys.argv) > 3 else 600.0

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4)
srv.settimeout(dur)
print("[kstream] listening on %d, out=%s, dur=%ss" % (port, out, dur), flush=True)

t0 = time.time()
total = 0
with open(out, "wb") as f:
    while time.time() - t0 < dur:
        try:
            c, addr = srv.accept()
        except socket.timeout:
            print("[kstream] accept timeout, done", flush=True)
            break
        print("[kstream] accepted from %s" % (addr,), flush=True)
        c.settimeout(5)
        while True:
            try:
                b = c.recv(65536)
            except socket.timeout:
                # device side idle, keep waiting (it may go silent right before a panic)
                if time.time() - t0 >= dur:
                    break
                continue
            except OSError as e:
                print("[kstream] recv error: %r" % (e,), flush=True)
                break
            if not b:
                print("[kstream] peer closed", flush=True)
                break
            f.write(b)
            f.flush()
            total += len(b)
        c.close()
print("[kstream] total bytes=%d" % total, flush=True)
