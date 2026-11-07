import struct, sys

def parse(path):
    d = open(path, 'rb').read()
    u64 = lambda o: struct.unpack('<Q', d[o:o+8])[0]
    u32 = lambda o: struct.unpack('<I', d[o:o+4])[0]
    print('== %s  size=%d' % (path, len(d)))
    print('magic=%s ver=%d.%d alg=%d' % (d[:4], u32(4), u32(8), u32(28)))
    auth, aux = u64(12), u64(20)
    doff, dsz = u64(96), u64(104)
    print('auth_blk=%d aux_blk=%d desc_off=%d desc_sz=%d flags=0x%x rb_loc=%d' %
          (auth, aux, doff, dsz, u32(120), u32(124)))
    print('release=%s' % d[128:176].split(b'\x00')[0].decode('utf8', 'replace'))
    p, end = doff, doff + dsz
    n = 0
    while p + 16 <= end:
        tag, nbf = u64(p), u64(p + 8)
        body = p + 16
        if tag == 0:
            koff, ksz, voff, vsz = u64(body), u64(body+8), u64(body+16), u64(body+24)
            k = d[body+koff:body+koff+ksz].split(b'\x00')[0].decode('utf8', 'replace')
            v = d[body+voff:body+voff+vsz].rstrip(b'\x00').decode('utf8', 'replace')
            print('  PROP     %-44s = %s' % (k, v))
        elif tag == 1:
            dmv, pso, nlv, hs = u32(body), u32(body+4), u32(body+8), u32(body+12)
            dss = u64(body + 24)
            salt = d[body+32:body+32+nlv].hex()
            nm = d[body+pso:body+pso+64].split(b'\x00')[0].decode('utf8', 'replace')
            print('  HASHTREE %-16s dmverity=%d hashalg=%d salt=%s data_blocks=%d' %
                  (nm, dmv, hs, salt, dss))
        elif tag == 2:
            nm = d[body+32:body+32+64].split(b'\x00')[0].decode('utf8', 'replace')
            print('  HASH     %-16s' % nm)
        elif tag == 3:
            print('  KERNELCMDLINE')
        elif tag == 4:
            nm = d[body+16:body+16+64].split(b'\x00')[0].decode('utf8', 'replace')
            print('  CHAIN    %-16s rollback_loc=%d' % (nm, u32(body+12)))
        else:
            print('  TAG%d len=%d' % (tag, nbf))
        p = body + ((nbf + 7) // 8) * 8
        n += 1
    print('  -> %d descriptors' % n)

for f in sys.argv[1:]:
    parse(f)
