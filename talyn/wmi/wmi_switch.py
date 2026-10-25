# Восстановление switch по коду WMI-команды (r2) в диспетчере fw Talyn: cmp/beq + таблицы ldw.x.as
import sys, re, struct, collections
T, img, lo, hi = sys.argv[1], sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4], 16)
L = []
for l in open(f'{T}/out3/{img}_fw/listing.dis'):
    p = l.rstrip('\n').split('\t'); L.append((int(p[0].split(':')[-1], 16), p[1], p[2]))
idx = {a: i for i, (a, _, _) in enumerate(L)}
data = open(f'{T}/seg/{img.split("_",1)[0] and img.replace("_fw","")}/a00000.bin', 'rb').read() if False else open(f'{T}/seg/{img}/a00000.bin', 'rb').read()
h16 = lambda a: struct.unpack_from('<h', data, a - 0x800000)[0]
cases = {}
for i, (a, ins, fn) in enumerate(L):
    if not (lo <= a < hi): continue
    m = re.match(r'_?cmp(?:_s)? r2,(0x[0-9a-f]+)', ins)
    if m and i + 1 < len(L):
        n = re.match(r'_?beq(?:_s)? 0x([0-9a-f]+)', L[i + 1][1])
        if n: cases[int(m.group(1), 16)] = int(n.group(1), 16)
    base = None
    m = re.match(r'_?sub(?:_s)? r1,r2,(0x[0-9a-f]+)', ins)
    if m: base = int(m.group(1), 16)
    m2 = re.match(r'_?sub(?:_s)? r1,r1,(0x[0-9a-f]+)', ins)
    if m2 and i > 0 and re.match(r'_?mov(?:_s)? r1,r2$', L[i - 1][1]): base = int(m2.group(1), 16)
    if base is not None:
        c = t = ad = None
        for k in range(i + 1, min(i + 7, len(L))):
            c = c or re.match(r'_?cmp(?:_s)? r1,(0x[0-9a-f]+)', L[k][1])
            t = t or re.match(r'_?ldw\.x\.as r1,\[(0x[0-9a-f]+),r1\]', L[k][1])
            ad = ad or re.match(r'_?add r0,pcl=(0x[0-9a-f]+),(0x[0-9a-f]+)', L[k][1])
        if c and t and ad:
            n = int(c.group(1), 16); tab = int(t.group(1), 16); pc = int(ad.group(1), 16) + int(ad.group(2), 16)
            for k in range(n + 1): cases.setdefault(base + k, pc + 2 * h16(tab + 2 * k))
# по каждому case: первая строка журнала и первый вызов
tab65 = None
b = open(f'{T}/plain/' + sys.argv[5], 'rb').read(); o = 0
while o + 8 <= len(b):
    t, fl, sz = struct.unpack_from('<HHI', b, o)
    if o + 8 + sz > len(b): break
    if t == 0x65 and tab65 is None: tab65 = b[o + 8:o + 8 + sz]
    o = (o + 8 + sz + 3) & ~3
def s_at(off):
    j = tab65.find(b'\0', off); return tab65[off:j].decode('latin1')
funcs = {}
for l in open(f'{T}/out3/{img}_fw/funcs.txt'):
    a, sz, n = l.split()[:3]; funcs[int(a.split(':')[-1], 16)] = n
LOGF = {0x3a340, 0x3a3a8, 0x3a41c, 0x3a49c, 0x3a4fc}
cnt = collections.Counter(cases.values()); default = cnt.most_common(1)[0][0]
out = []
for cid in sorted(cases):
    tgt = cases[cid]
    if tgt == default: continue
    j = idx.get(tgt); s = call = ''
    for k in range(j, min(j + 24, len(L))) if j is not None else []:
        ins = L[k][1]
        mm = re.search(r'0x(1[0-9a-f]{6})\b', ins)
        if mm and not s:
            try: s = s_at(int(mm.group(1), 16) & 0xffffff)
            except Exception: pass
        cm = re.match(r'_?(?:bl|jl)(?:\.d)?(?:_s)? 0x([0-9a-f]+)', ins)
        if cm and not call:
            ca = int(cm.group(1), 16)
            if ca not in LOGF: call = funcs.get(ca, hex(ca))
        if re.match(r'_?(?:b|j)(?:_s)?(?:\.d)? ', ins) and k > j and s: break
    out.append((cid, tgt, s, call))
print('cases', len(cases), 'default', hex(default), 'handled', len(out))
with open(f'{T}/wmi/{img}_wmi.tsv', 'w') as f:
    f.write('# id\tcase\tстрока журнала\tпервый вызов\n')
    for cid, tgt, s, call in out: f.write('0x%04x\t0x%05x\t%s\t%s\n' % (cid, tgt, s.replace('\t', ' '), call))
