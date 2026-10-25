# Карта обращений к регистрам (0x880000..0x8bffff) по листингу Ghidra: база (mov/add) + смещение в ld/st.
import sys, re, collections
lst, out = sys.argv[1], sys.argv[2]
LO, HI = 0x880000, 0x8c0000
num = lambda s: int(s, 16) if s.lower().lstrip('-').startswith('0x') else int(s)
def val(s):
    s = s.strip()
    neg = s.startswith('-'); s = s.lstrip('-')
    try: v = int(s, 16) if s.startswith('0x') else int(s)
    except ValueError: return None
    return -v if neg else v
CLOB = {'r%d' % i for i in range(13)} | {'blink'}
acc = collections.defaultdict(lambda: {'r': 0, 'w': 0, 'fn': collections.Counter(), 'vals': collections.Counter()})
regs = {}; cur = None
for line in open(lst):
    p = line.rstrip('\n').split('\t')
    if len(p) < 3: continue
    addr, ins, fn = p[0], p[1], p[2]
    if fn != cur: regs = {}; cur = fn
    m = re.match(r'_?([a-z0-9_.]+)\s*(.*)', ins)
    if not m: continue
    op, args = m.group(1), m.group(2)
    base_op = op.split('.')[0].rstrip('_s') if op.endswith('_s') else op.split('.')[0]
    ops = [a.strip() for a in re.split(r',(?![^\[]*\])', args)] if args else []
    if base_op in ('bl', 'jl', 'blal') or op.startswith(('bl', 'jl')):
        for r in CLOB: regs.pop(r, None)
        continue
    mem = re.search(r'\[([a-z0-9]+)(?:,([-0-9a-fx]+))?\]', args)
    if base_op in ('ld', 'ldb', 'ldw', 'st', 'stb', 'stw') or op.startswith(('ld', 'st')):
        if mem:
            b = mem.group(1); off = val(mem.group(2)) if mem.group(2) else 0
            ba = regs.get(b) if not b.startswith('0x') else val(b)
            if ba is not None and off is not None:
                a = (ba + off) & 0xffffffff
                if LO <= a < HI:
                    e = acc[a]; w = op.startswith('st')
                    e['w' if w else 'r'] += 1; e['fn'][fn or addr] += 1
                    if w and ops:
                        v = regs.get(ops[0], val(ops[0]))
                        if v is not None: e['vals'][v & 0xffffffff] += 1
        if op.startswith('ld') and ops: regs.pop(ops[0], None)
        continue
    if base_op in ('mov',) and len(ops) >= 2:
        v = val(ops[1]); v = regs.get(ops[1]) if v is None else v
        if v is None: regs.pop(ops[0], None)
        else: regs[ops[0]] = v & 0xffffffff
        continue
    if base_op in ('add', 'sub') and len(ops) >= 2:
        d = ops[0]; srcs = ops[1:] if len(ops) == 3 else [ops[0], ops[1]]
        a = regs.get(srcs[0], val(srcs[0])); b = regs.get(srcs[1], val(srcs[1]))
        if a is not None and b is not None: regs[d] = (a + b if base_op == 'add' else a - b) & 0xffffffff
        else: regs.pop(d, None)
        continue
    if ops and re.match(r'r\d+$|blink$|fp$|gp$', ops[0]): regs.pop(ops[0], None)
with open(out, 'w') as f:
    f.write('# адрес\tчтений\tзаписей\tфункции(число)\tзаписываемые константы\n')
    for a in sorted(acc):
        e = acc[a]
        fns = ','.join('%s(%d)' % (k, c) for k, c in e['fn'].most_common(6))
        vals = ','.join('0x%x' % v for v, _ in e['vals'].most_common(5))
        f.write('0x%06x\t%d\t%d\t%s\t%s\n' % (a, e['r'], e['w'], fns, vals))
print('регистров', len(acc), 'обращений', sum(e['r'] + e['w'] for e in acc.values()))
