#!/usr/bin/env python3
"""tdm_regs.py — регистры TDMA-механизма Terragraph 10.11 и их наличие у Sparrow.

Набор функций: имена по строкам журнала с tdm/slot/gps/mtpo/clbr/Terragraph/frame_timer/scheduler
+ их вызываемые на глубину 1 (по decomp.c). Регистры — по regmap/tdm/tg11_{fw,uc}.tsv.
Наличие у Sparrow — по regmap/sparrow_applicability.tsv (если адрес там есть) и снимкам sparrow_rgf/.
Выход: regmap/tdm/tdm_regs.tsv и сводка в stdout."""
import os, re, struct, collections, sys
# Данные Talyn (каталог talyn/ закрытого SparRAW-pro: plain/, seg/, out3/, names/, regmap/*.tsv, sparrow_rgf/)
T = os.environ.get('TALYN_DATA') or sys.exit('TALYN_DATA: каталог данных Talyn')
RA = os.environ.get('REGAUDIT') or sys.exit('REGAUDIT: каталог с inventory2.tsv')
PAT = re.compile(r'tdm|slot|gps|mtpo|clbr|terragraph|frame_timer|scheduler|sched_func|bwgd|fb_', re.I)
DEAD = 0xdeadbeaf

def blocks(k):
    src = open('%s/out3/tg_10.11.0.92_%s/decomp.c' % (T, k), errors='replace').read()
    for b in re.split(r'\n(?=/\* ===== )', src):
        m = re.match(r'/\* ===== (\S+) @ ram:([0-9a-f]+)', b.strip())
        if m: yield m.group(1), b

def words(p, base):
    b = open(p, 'rb').read()
    return {base + 4 * i: w for i, w in enumerate(struct.unpack('<%dI' % (len(b) // 4), b))}

snap = collections.defaultdict(set)
for f in os.listdir(T + '/sparrow_rgf'):
    for suf, base in (('.rgf.bin', 0x880000), ('.agc.bin', 0x88a000), ('.rgf_ext.bin', 0x88b000), ('.mac_rgf_ext.bin', 0x88c000)):
        if f.endswith(suf):
            for a, w in words(T + '/sparrow_rgf/' + f, base).items(): snap[a].add(w)
probe = {int(r[0], 16): r[1] for r in (l.rstrip('\n').split('\t') for l in open(T + '/sparrow_rgf/fw_probe.tsv')) if r[0].startswith('0x')}
spar = {}
for l in open(RA + '/inventory2.tsv'):
    r = l.split('\t')
    if re.fullmatch(r'0x[0-9a-f]+', r[0]): spar.setdefault(int(r[0], 16), r[1])

def sparrow_state(a):
    if a in spar: return 'есть (наша fw: %s)' % spar[a]
    v = snap.get(a)
    if v:
        if v == {DEAD}: return 'нет (deadbeaf)'
        return 'есть (%s)' % ' '.join('%x' % x for x in sorted(v)[:3])
    if a in probe: return {'HANG_CHIP': 'нет (вешает чип)', 'STALL': 'нет (не завершается)'}.get(probe[a], 'есть (%s)' % probe[a])
    if 0x88c43c <= a < 0x88c500: return 'нет (deadbeaf)'
    if a >= 0x88c500: return 'нет (вне шины)'
    return '?'

rows = []
for k in ('uc', 'fw'):
    B = dict(blocks(k))
    seed = {n for n in B if PAT.search(n)}
    sel = set(seed)
    for n in seed:
        for c in re.findall(r'\b((?:FUN_ram|file|fwlog|thunk)_\w+)\s*\(', B[n]):
            if c in B: sel.add(c)
    for l in open('%s/regmap/tdm/tg11_%s.tsv' % (T, k)):
        if l.startswith('#'): continue
        r = l.rstrip('\n').split('\t')
        fns = [re.sub(r'\(\d+\)$', '', f) for f in r[3].split(',') if f]
        hit = [f for f in fns if f in sel]
        if not hit: continue
        a = int(r[0], 16)
        rows.append([r[0], k, r[1], r[2], sparrow_state(a), r[4] if len(r) > 4 else '',
                     ','.join(sorted(set(hit), key=lambda f: (f not in seed, f))[:5])])
with open(T + '/regmap/tdm/tdm_regs.tsv', 'w') as f:
    f.write('# адрес\tfw/uc\tчтений\tзаписей\tSparrow\tконстанты Terragraph\tTDMA-функции (сначала по имени)\n')
    for r in rows: f.write('\t'.join(r) + '\n')
c = collections.Counter(r[4].split(' ')[0] for r in rows)
print('регистров TDMA', len(rows), dict(c))
