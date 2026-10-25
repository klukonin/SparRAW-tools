#!/usr/bin/env python3
"""sparrow_applic.py — какие регистры Talyn 7.5 (карта обращений fw+uc) применимы к Sparrow.

Источники Sparrow: снимки RGF (sparrow_rgf/*.bin: 0x880000..0x889fff в 4 состояниях, AGC_tbl,
rgf_ext и mac_rgf_ext с vendor 6.2 AP), список регистров нашей прошивки Sparrow
(REGAUDIT/inventory2.tsv), каталог имён Talyn (REGAUDIT/talyn-regs.tsv).
Классы:
  A — общий: регистр использует прошивка Sparrow;
  B — есть в железе Sparrow (не 0xdeadbeaf), прошивка Sparrow его не трогает;
  C — нет в Sparrow (0xdeadbeaf во всех снимках);
  D — вне карты памяти Sparrow и не проверено.
Адреса вне карты драйвера проверены чтением ядром fw (sparrow_rgf/fw_probe.tsv): значение — B/C по нему,
зависание чипа или незавершённое чтение — C. Поведение по снимкам: const, live (меняется за 1 с в простое),
state (зависит от состояния: down/AP/STA/iperf/канал).
Выход: regmap/sparrow_applicability.tsv; сводка по блокам 0x100 — stdout."""
import os, re, sys, struct, collections
# Данные Talyn (каталог talyn/ закрытого SparRAW-pro: plain/, seg/, out3/, names/, regmap/*.tsv, sparrow_rgf/)
T = os.environ.get('TALYN_DATA') or sys.exit('TALYN_DATA: каталог данных Talyn')
RA = os.environ.get('REGAUDIT') or sys.exit('REGAUDIT: каталог с inventory2.tsv и talyn-regs.tsv')
DEAD = 0xdeadbeaf

def words(path, base):
    b = open(path, 'rb').read()
    return {base + 4 * i: w for i, w in enumerate(struct.unpack('<%dI' % (len(b) // 4), b))}

snaps = collections.defaultdict(dict)          # адрес -> {состояние: значение}
STATES = ('down', 'vendor_ap', 'exp_ap', 'exp_ch3',
          'our_sta_idle_a', 'our_sta_idle_b', 'our_sta_iperf', 'our_down')
for st in STATES:
    for a, w in words('%s/sparrow_rgf/%s.rgf.bin' % (T, st), 0x880000).items(): snaps[a][st] = w
    for a, w in words('%s/sparrow_rgf/%s.agc.bin' % (T, st), 0x88a000).items(): snaps[a][st] = w
    for blob, base in (('rgf_ext', 0x88b000), ('mac_rgf_ext', 0x88c000)):
        p = '%s/sparrow_rgf/%s.%s.bin' % (T, st, blob)
        if os.path.exists(p):
            for a, w in words(p, base).items(): snaps[a][st] = w

# чтения ядром fw (poke) за пределами карты драйвера: адрес -> значение | HANG_CHIP | STALL
probe = {}
for l in open(T + '/sparrow_rgf/fw_probe.tsv'):
    r = l.rstrip('\n').split('\t')
    if r[0].startswith('0x'): probe[int(r[0], 16)] = r[1]
# у Sparrow mac_rgf_ext реально до 0x88c438, дальше до 0x88c4ff — 0xdeadbeaf, с 0x88c500 чтение вешает чип;
# остальные области вне карты (0x88d000+, 0x88e000+, 0x89a000+, 0x8b0000+) — чтение не завершается
def probe_of(a):
    if a in probe: return probe[a]
    if 0x88c500 <= a < 0x88d000: return 'HANG_CHIP'
    if a >= 0x88d000: return 'STALL'
    return None

def behaviour(s):
    """Поведение по снимкам: const / live (меняется за 1 с в простое) / state (зависит от состояния)."""
    if not s or all(v == DEAD for v in s.values()): return ''
    a, b = s.get('our_sta_idle_a'), s.get('our_sta_idle_b')
    if a is not None and b is not None and a != b: return 'live'
    return 'const' if len(set(s.values())) == 1 else 'state'

# прошивка Sparrow (наша open): адрес -> имя
spar = {}
for l in open(RA + '/inventory2.tsv'):
    r = l.rstrip('\n').split('\t')
    if re.fullmatch(r'0x[0-9a-f]+', r[0]): spar.setdefault(int(r[0], 16), r[1])

# имена Talyn: адрес -> имя
tname = {}
for l in open(RA + '/talyn-regs.tsv'):
    r = l.rstrip('\n').split('\t')
    if re.fullmatch(r'0x[0-9a-f]+', r[0]) and r[1]: tname.setdefault(int(r[0], 16), r[1])

# имена функций Talyn: старое имя -> человеческое
human = {}
for k in ('fw', 'uc'):
    addr2new = {}
    p = T + '/names/tl_7.5.3.115_%s_human.tsv' % k
    for l in open(p):
        r = l.rstrip('\n').split('\t')
        if r[0].startswith('0x') and len(r) > 3 and r[3] in ('H', 'M'): addr2new[int(r[0], 16)] = r[2]
    for l in open(T + '/out3/tl_7.5.3.115_%s/funcs.txt' % k):
        a, _, n = l.split()[:3]
        a = int(a[4:], 16)
        if a in addr2new: human[(k, n)] = addr2new[a]

# карта обращений Talyn
tal = collections.defaultdict(lambda: {'side': set(), 'rd': 0, 'wr': 0, 'fn': [], 'const': set()})
for k in ('fw', 'uc'):
    for l in open(T + '/regmap/tl75_%s.tsv' % k):
        if l.startswith('#'): continue
        r = l.rstrip('\n').split('\t')
        a = int(r[0], 16); e = tal[a]
        e['side'].add(k); e['rd'] += int(r[1]); e['wr'] += int(r[2])
        for f in filter(None, r[3].split(',')):
            n = re.sub(r'\(\d+\)$', '', f)
            if not n.startswith('ram:'): e['fn'].append(human.get((k, n), n))
        if len(r) > 4:
            for c in re.findall(r'0x[0-9a-f]+', r[4]): e['const'].add(int(c, 16))

def module(fns):
    c = collections.Counter(re.split(r'_', f.replace('fwlog_', '').replace('file_', ''))[0] for f in fns)
    return ','.join(m for m, _ in c.most_common(2))

def shift_cand(a, consts):
    """Сдвинутый блок: та же характерная константа рядом (±0x100) в снимке vendor_ap."""
    out = []
    for c in consts:
        if c <= 0xff or c in (0xffffffff, DEAD): continue
        for d in range(-0x100, 0x104, 4):
            if d and snaps.get(a + d, {}).get('vendor_ap') == c: out.append('%+#x' % d)
    return ','.join(sorted(set(out))[:3])

rows = []; cls_cnt = collections.Counter(); blk = collections.defaultdict(collections.Counter)
for a in sorted(tal):
    e = tal[a]; s = snaps.get(a)
    pr = probe_of(a) if not s else None
    if pr and pr.startswith('0x'):
        s = {'fw_probe': int(pr, 16)}
    if a in spar: cls, how = 'A', 'снимок'
    elif s: cls, how = ('C', 'снимок 0xdeadbeaf') if all(v == DEAD for v in s.values()) else ('B', 'снимок' if not pr else 'чтение fw')
    elif pr: cls, how = 'C', {'HANG_CHIP': 'чтение fw вешает чип', 'STALL': 'чтение fw не завершается'}[pr]
    else: cls, how = 'D', 'не проверено'
    vals = sorted(set(s.values())) if s else []
    same = ''
    if s and e['const']:
        same = 'да' if e['const'] & set(vals) else 'нет'
    sh = shift_cand(a, e['const']) if cls in ('C', 'B') and same != 'да' else ''
    rows.append(['%#08x' % a, cls, '+'.join(sorted(e['side'])), str(e['rd']), str(e['wr']),
                 tname.get(a, ''), spar.get(a, ''), module(e['fn']),
                 ' '.join('%08x' % v for v in vals[:4]), ' '.join('%#x' % c for c in sorted(e['const'])[:4]),
                 same, sh, behaviour(s) if 'fw_probe' not in (s or {}) else 'const?', how,
                 ','.join(sorted(set(e['fn']))[:4])])
    cls_cnt[cls] += 1; blk[a & ~0xff][cls] += 1

with open(T + '/regmap/sparrow_applicability.tsv', 'w') as f:
    f.write('# адрес\tкласс\tfw/uc\tчтений\tзаписей\tимя Talyn\tимя Sparrow\tмодуль Talyn\t'
            'значения Sparrow\tконстанты Talyn\tконстанта совпала\tсдвиг-кандидат\tповедение\tпроверка\tфункции Talyn\n')
    for r in rows: f.write('\t'.join(r) + '\n')
print('итого', len(rows), dict(sorted(cls_cnt.items())))
print('# блок 0x100: A B C D')
for b in sorted(blk):
    c = blk[b]; print('%#08x %3d %3d %3d %3d' % (b, c['A'], c['B'], c['C'], c['D']))
