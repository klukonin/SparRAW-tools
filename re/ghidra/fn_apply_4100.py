# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Применить восстановленные имена к проекту fw4100.
# Аргументы: <FN-NAMES-4100.raw> <FN-FILEMAP-4100.txt>
# МЕНЯЕТ ПРОЕКТ. Не перезаписывает уже осмысленные (не FUN_*) имена.
from collections import Counter
from ghidra.program.model.symbol import SourceType
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

raw, fmap_path = getScriptArgs()[0], getScriptArgs()[1]

rows = []
for l in open(raw):
    if not l.startswith('ROW'): continue
    p = l.split(None, 5)
    addr = int(p[1], 16); name = p[2]; sz = int(p[3])
    ev = p[5].split('|', 1)[1].strip() if len(p) > 5 and '|' in p[5] else ''
    rows.append((addr, name, sz, ev))

cnt = Counter(n for _, n, _, _ in rows if n != '?')
GENERIC = {n for n, c in cnt.items() if c > 3}      # макросы/теги, не имена
print('отброшено как не-имена (>3 функций): %s' % sorted(GENERIC))

fmap = {}
for l in open(fmap_path):
    p = l.split()
    if len(p) >= 2 and p[0].startswith('0x'):
        fmap[int(p[0], 16)] = p[1]

used = Counter()
applied = kept = skipped = 0
for addr, name, sz, ev in rows:
    f = fm.getFunctionContaining(sp.getAddress(addr))
    if not f or f.getEntryPoint().getOffset() != addr: continue
    cur = f.getName()
    src = fmap.get(addr)
    note = []
    if src: note.append('source: %s' % src)
    if ev: note.append('log: %s' % ev[:110])
    if name != '?' and name not in GENERIC:
        used[name] += 1
        final = name if used[name] == 1 else '%s__%d' % (name, used[name])
        if cur.startswith(('FUN_', 'thunk_FUN_')):
            f.setName(final, SourceType.ANALYSIS)
            note.append('recovered from log strings')
            applied += 1
        else:
            note.append('log-string name: %s (kept existing %s)' % (final, cur))
            kept += 1
    else:
        skipped += 1
    if note:
        listing.setComment(sp.getAddress(addr), 3, '\n'.join(note))   # 3 = PLATE

# атрибуция по исходникам для функций БЕЗ имени
extra = 0
for addr, src in fmap.items():
    f = fm.getFunctionContaining(sp.getAddress(addr))
    if not f or f.getEntryPoint().getOffset() != addr: continue
    if listing.getComment(3, sp.getAddress(addr)): continue
    listing.setComment(sp.getAddress(addr), 3, 'source: %s' % src)
    extra += 1

print('APPLIED %d  KEPT_EXISTING %d  NO_NAME %d  FILE_ONLY_COMMENTS %d'
      % (applied, kept, skipped, extra))
