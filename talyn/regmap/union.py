#!/usr/bin/env python3
"""union.py — сводная карта обращений к периферии 0x880000..0x8bffff по всем разобранным прошивкам
(Sparrow всех версий, Talyn, Terragraph), нашей open fw и драйверу wil6210, с поведением слова на Sparrow
по снимкам (sparrow_rgf/) и пробам fw (fw_probe.tsv). Пишет regmap/union.tsv; печатает сводку.

Поведение: dead (0xdeadbeaf во всех снимках), zero, const, state (зависит от состояния), live (меняется за
1 с в простое STA), hang/stall (проба fw: чтение вешает чип / не завершается), '' — нет данных.
6.2 = Ghidra-карта 6.2.0.1000 (openwrt и сборка MikroTik) ∪ REGS-62 ∪ REGS-KNOWN (дерево 6.2)."""
import os, re, sys, glob, struct, collections
# Данные Talyn (каталог talyn/ закрытого SparRAW-pro: plain/, seg/, out3/, names/, regmap/*.tsv, sparrow_rgf/)
T = os.environ.get('TALYN_DATA') or sys.exit('TALYN_DATA: каталог данных Talyn')
# Рабочее дерево SparRAW (SparRAW-firmware, SparRAW-driver) и списки регистров нашей прошивки
SP = os.environ.get('SPARRAW') or sys.exit('SPARRAW: каталог с SparRAW-firmware и SparRAW-driver')
RA = os.environ.get('REGAUDIT') or sys.exit('REGAUDIT: каталог с inventory2.tsv и talyn-regs.tsv')
DEAD = 0xdeadbeaf
LO, HI = 0x880000, 0x8c0000

SPARROW = ['sp_1.4.1.7698', 'sp_4.1.0.59', 'sp_4.1.0.7626', 'sp_4.1.0.1000', 'sp_5.2.0.18', 'sp_6.1.0.40',
           'sp_6.2.0.225']
SP62 = ['sp_6.2.0.1000', 'sp_6.2.0.1000mt']
TALYN = ['tl_7.1.3.980', 'tl_7.1.3.1158', 'tl75', 'tg_10.11.0.92']

# имена функций: (образ, вид, имя Ghidra) -> имя из строк журнала / человеческое
fname = {}
def load_names(img, k, path):
    if not os.path.exists(path): return
    for l in open(path):
        r = l.rstrip('\n').split('\t')
        if len(r) >= 3 and r[0].startswith('FUN_'): fname[(img, k, r[0])] = 'fwlog_' + r[2]
for k in ('fw', 'uc'):
    load_names('sp_4.1.0.1000', k, T + '/names/sp/sp_4.1.0.1000_%s.txt' % k)
    for img in SP62: load_names(img, k, T + '/names/sp/sp_6.2.0.1000mt_%s.txt' % k)
    hp = T + '/names/tl_7.5.3.115_%s_human.tsv' % k
    if os.path.exists(hp):
        a2n = {int(r[0], 16): r[2] for r in (l.rstrip('\n').split('\t') for l in open(hp)) if r[0].startswith('0x') and r[3] in 'HM'}
        for l in open(T + '/out3/tl_7.5.3.115_%s/funcs.txt' % k):
            a, _, n = l.split()[:3]
            if int(a[4:], 16) in a2n: fname[('tl75', k, n)] = a2n[int(a[4:], 16)]

use = collections.defaultdict(lambda: collections.defaultdict(set))   # адрес -> источник -> {функции}
wconst = collections.defaultdict(set)
def load_regmap(img, k, path):
    if not os.path.exists(path): return False
    for l in open(path):
        if l.startswith('#'): continue
        r = l.rstrip('\n').split('\t'); a = int(r[0], 16)
        fns = {fname.get((img, k, re.sub(r'\(\d+\)$', '', f)), re.sub(r'\(\d+\)$', '', f)) for f in r[3].split(',') if f}
        use[a]['%s:%s' % (img, k)] |= fns
        if img in SPARROW and len(r) > 4:
            for c in re.findall(r'0x[0-9a-f]+', r[4]): wconst[a].add(c)
    return True
missing = []
for img in SPARROW + SP62 + TALYN:
    for k in ('fw', 'uc'):
        if not load_regmap(img, k, T + '/regmap/%s_%s.tsv' % (img, k)): missing.append('%s:%s' % (img, k))

# дерево 6.2: REGS-62 / REGS-KNOWN — адреса и имена
name62 = {}
for l in open(SP + '/SparRAW-firmware/6.2/ref/REGS-62.md'):
    m = re.match(r'\| (0x88[0-9a-f]{4}) \| ([^|]*)\|', l)
    if m: name62[int(m.group(1), 16)] = m.group(2).strip(); use[int(m.group(1), 16)]['6.2tree'].add('')
for l in open(SP + '/SparRAW-firmware/6.2/ref/REGS-KNOWN.txt'):
    m = re.match(r'(0x88[0-9a-f]{4})\s+(\S+)', l)
    if m: name62.setdefault(int(m.group(1), 16), m.group(2)); use[int(m.group(1), 16)]['6.2tree'].add('')
# наша open fw
for l in open(RA + '/inventory2.tsv'):
    r = l.rstrip('\n').split('\t')
    if re.fullmatch(r'0x[0-9a-f]+', r[0]): use[int(r[0], 16)]['open'].add(r[1])
# драйвер wil6210: define'ы с адресами в заголовках и их использование в .c; ICR-блоки — база + 0..0x1c
DRV = SP + '/SparRAW-driver/drivers/net/wireless/ath/wil6210'
src = ''.join(open(p, errors='replace').read() for p in glob.glob(DRV + '/*.c'))
for p in glob.glob(DRV + '/*.h'):
    for m in re.finditer(r'#define\s+(\w+)\s+\(?(0x88[0-9a-fA-F]{4})', open(p, errors='replace').read()):
        n, a = m.group(1), int(m.group(2), 16)
        if n == 'WIL6210_FW_HOST_OFF' or not re.search(r'\b' + n + r'\b', src): continue
        span = 0x20 if 'ICR' in n or n.endswith('_ICC') else 4
        for o in range(0, span, 4): use[a + o]['driver'].add(n)
for m in re.finditer(r'\b(0x88[0-9a-fA-F]{4})\b', src): use[int(m.group(1), 16)]['driver'].add('literal')
# имена Talyn
tname = {}
for l in open(RA + '/talyn-regs.tsv'):
    r = l.rstrip('\n').split('\t')
    if re.fullmatch(r'0x[0-9a-f]+', r[0]) and r[1]: tname.setdefault(int(r[0], 16), r[1])

# снимки Sparrow и пробы
def words(p, base):
    b = open(p, 'rb').read(); return {base + 4 * i: w for i, w in enumerate(struct.unpack('<%dI' % (len(b) // 4), b))}
snaps = collections.defaultdict(dict)
for st in ('down', 'vendor_ap', 'exp_ap', 'exp_ch3', 'our_sta_idle_a', 'our_sta_idle_b', 'our_sta_iperf', 'our_down'):
    for ext, base in (('rgf', 0x880000), ('agc', 0x88a000), ('rgf_ext', 0x88b000), ('mac_rgf_ext', 0x88c000)):
        p = '%s/sparrow_rgf/%s.%s.bin' % (T, st, ext)
        if os.path.exists(p):
            for a, w in words(p, base).items(): snaps[a][st] = w
probe = {}
for l in open(T + '/sparrow_rgf/fw_probe.tsv'):
    r = l.rstrip('\n').split('\t')
    if r[0].startswith('0x'): probe[int(r[0], 16)] = r[1]
def behaviour(a):
    s = snaps.get(a)
    if not s:
        if a in probe:
            v = probe[a]
            if v in ('HANG_CHIP', 'STALL'): return {'HANG_CHIP': 'hang', 'STALL': 'stall'}[v]
            return 'dead' if v == '0xdeadbeaf' else ('zero' if int(v, 16) == 0 else 'const')
        if 0x88c43c <= a < 0x88c500: return 'dead'
        if 0x88c500 <= a < 0x88d000: return 'hang'
        if a >= 0x88d000: return 'stall'
        return ''
    if all(v == DEAD for v in s.values()): return 'dead'
    x, y = s.get('our_sta_idle_a'), s.get('our_sta_idle_b')
    if x is not None and y is not None and x != y: return 'live'
    vs = set(s.values())
    return ('zero' if vs == {0} else 'const') if len(vs) == 1 else 'state'

LIVE = {'zero', 'const', 'state', 'live'}
rows = []
for a in sorted(set(use) | {a for a in snaps if LO <= a < HI}):
    if not LO <= a < HI: continue
    u = use.get(a, {})
    spv = sorted({s.split(':')[0] for s in u if s.split(':')[0] in SPARROW})
    in62 = any(s.split(':')[0] in SP62 for s in u) or '6.2tree' in u
    tal = sorted({s.split(':')[0] for s in u if s.split(':')[0] in TALYN})
    fns = []
    for s in sorted(u):
        if s.split(':')[0] in SPARROW + SP62 + TALYN:
            named = sorted(f for f in u[s] if not f.startswith('FUN_') and not f.startswith('ram:'))
            if named: fns.append('%s=%s' % (s, ','.join(named[:3])))
    s = snaps.get(a, {})
    vals = ' '.join('%08x' % v for v in sorted(set(s.values()))[:4])
    rows.append(dict(a=a, sp=','.join(spv), s62='y' if in62 else '', open='y' if 'open' in u else '',
                     drv=','.join(sorted(u['driver']))[:60] if 'driver' in u else '', tal=','.join(tal),
                     beh=behaviour(a), vals=vals, wc=' '.join(sorted(wconst.get(a, ()))[:4]),
                     n62=name62.get(a, ''), tn=tname.get(a, ''), fns=' ; '.join(fns)[:400]))
cols = ['a', 'sp', 's62', 'open', 'drv', 'tal', 'beh', 'vals', 'wc', 'n62', 'tn', 'fns']
with open(T + '/regmap/union.tsv', 'w') as f:
    f.write('# адрес\tSparrow (кроме 6.2.0.1000)\t6.2.0.1000\topen\tдрайвер\tTalyn/TG\tповедение Sparrow\t'
            'значения Sparrow\tконстанты Sparrow-fw\tимя 6.2\tимя Talyn\tфункции (образ:вид=имена)\n')
    for r in rows: f.write('\t'.join(['%#08x' % r['a']] + [r[c] for c in cols[1:]]) + '\n')
known = lambda r: r['s62'] or r['open'] or r['drv']
A = [r for r in rows if r['sp'] and not known(r) and r['beh'] in LIVE]
B = [r for r in rows if r['tal'] and not r['sp'] and not known(r) and r['beh'] in LIVE]
C = [r for r in rows if not r['sp'] and not r['tal'] and not known(r) and r['beh'] in ('const', 'state', 'live')]
print('адресов', len(rows), 'нет:', missing)
print('(а) только старые/иные Sparrow-fw, живые:', len(A))
print('(б) только Talyn/TG, живые:', len(B))
print('(в) тёмные (никто, ненулевые):', len(C), collections.Counter(r['beh'] for r in C))
