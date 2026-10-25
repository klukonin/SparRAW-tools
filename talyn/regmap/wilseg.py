#!/usr/bin/env python3
"""wilseg.py <образ.fw> [<каталог seg>] — разбор контейнера wil6210 (fw.h: head{type,flags,size} + данные).
Без каталога печатает записи data/fill; с каталогом — собирает сегменты по регионам Sparrow
(хост: 0x8c0000 fw_code → ядро 0x0, 0x900000 fw_data → 0x800000, 0x920000 uc_code → 0x0,
0x940000 uc_data → 0x800000; sparrow_fw_mapping драйвера) в <хост>.bin + map.txt. В map.txt у кода
линковка 0 — код импортируется основным файлом (sp_run.sh), addblocks.py добавляет только данные."""
import sys, struct, os
REG = [(0x8c0000, 0x8fffff, 0x0, 'fw_code'), (0x900000, 0x907fff, 0x800000, 'fw_data'),
       (0x920000, 0x93ffff, 0x0, 'uc_code'), (0x940000, 0x947fff, 0x800000, 'uc_data')]
b = open(sys.argv[1], 'rb').read(); o = 0; recs = []
while o + 8 <= len(b):
    t, fl, sz = struct.unpack_from('<HHI', b, o); body = b[o + 8:o + 8 + sz]
    if t == 2: recs.append(('data', struct.unpack_from('<I', body)[0], body[4:]))
    elif t == 3:
        a, v, n = struct.unpack_from('<III', body); recs.append(('fill', a, struct.pack('<I', v) * (n // 4)))
    o += 8 + sz
if len(sys.argv) < 3:
    for k, a, d in recs: print(k, hex(a), len(d))
    sys.exit()
out = sys.argv[2]; os.makedirs(out, exist_ok=True); mp = []
for lo, hi, lnk, name in REG:
    rs = [(a, d) for k, a, d in recs if lo <= a <= hi]
    if not rs: continue
    end = max(a + len(d) for a, d in rs); buf = bytearray(end - lo)
    for a, d in rs: buf[a - lo:a - lo + len(d)] = d
    open('%s/%x.bin' % (out, lo), 'wb').write(buf)
    mp.append('0x%08x 0x%08x %s' % (lo, lnk, name))
open(out + '/map.txt', 'w').write('\n'.join(mp) + '\n')
print('\n'.join(mp))
