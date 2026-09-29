# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Назвать функции ucode по лог-строкам (таблица = запись 100 образа MikroTik).
# Аргумент: TSV "адрес<TAB>строка". МЕНЯЕТ ПРОЕКТ, только FUN_*.
import re
from collections import Counter, defaultdict
from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()

per = defaultdict(list)
for line in open(getScriptArgs()[0]):
    a, s = line.rstrip('\n').split('\t', 1)
    f = fm.getFunctionContaining(af.getAddress(int(a, 16)))
    if f:
        per[f].append(s)

def propose(strings):
    for s in strings:
        m = re.search(r'([A-Za-z_]\w*)::([A-Za-z_]\w*)', s)
        if m:
            return m.group(1) + '_' + m.group(2), s
    for s in strings:
        m = re.match(r'\s*([A-Za-z_]\w*)\s*\(', s)          # вида foo(): ...
        if m:
            return m.group(1), s
    for s in strings:
        t = re.sub(r'%[0-9a-zA-Z.#]*', '', s).strip()
        w = re.findall(r'[A-Za-z_]\w*', t)[:4]
        if len(w) >= 2:
            return '_'.join(w)[:48], s
    return None, None

props = {}
for f, ss in per.items():
    n, ev = propose(ss)
    if n:
        props[f] = (re.sub(r'[^0-9A-Za-z_]+', '_', n).strip('_'), ev)

cnt = Counter(n for n, _ in props.values())
GENERIC = {n for n, c in cnt.items() if c > 2}
applied = skipped = 0
for f, (n, ev) in props.items():
    if n in GENERIC or not f.getName().startswith('FUN_'):
        skipped += 1
        continue
    f.setName('uclog_' + n, SourceType.USER_DEFINED)
    old = f.getComment() or ''
    f.setComment((old + '\n' if old else '') + 'из лог-строки ucode: ' + ev)
    applied += 1
print('функций со строками: %d | назначено: %d | пропущено: %d' % (len(per), applied, skipped))
