import hashlib, os, re, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = BASE + '/logs/dump'
LOG = D + '/device_dump.log'

exp = {}
for line in open(LOG, encoding='utf8', errors='replace'):
    m = re.match(r'\[(OK|SIZE_MISMATCH|SKIP)\] (\S+) exp=(\d+) got=(\d+) rc=(-?\d+) t=(\d+)s sha256=(\w+)', line.strip())
    if m:
        exp[m.group(2)] = dict(status=m.group(1), exp=int(m.group(3)),
                               got=int(m.group(4)), sha=m.group(7), t=int(m.group(6)))

print('%-3s %-20s %12s %12s %-8s %s' % ('st', 'partition', 'device', 'local', 'time', 'sha256'))
ok = bad = 0
for name in sorted(exp):
    e = exp[name]
    p = os.path.join(D, name + '.img')
    if not os.path.exists(p):
        print('%-3s %-20s %12d %12s %-8s %s' % ('MISS', name, e['exp'], '-', '%ds' % e['t'], e['sha'][:16]))
        bad += 1
        continue
    n = os.path.getsize(p)
    h = hashlib.sha256(open(p, 'rb').read()).hexdigest() if n < 400 * 1024 * 1024 else None
    if h is None:
        # chunked read so multi-hundred-MB images never sit in RAM at once
        hh = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(8 << 20), b''):
                hh.update(chunk)
        h = hh.hexdigest()
    good = (n == e['exp']) and h.startswith(e['sha'])
    print('%-3s %-20s %12d %12d %-8s %s %s' % ('OK' if good else 'BAD', name, e['exp'], n,
                                                '%ds' % e['t'], h[:16], '' if good else '<<< MISMATCH'))
    ok += good
    bad += (not good)

print('\ntotal %d partitions, verified %d, abnormal %d' % (len(exp), ok, bad))
