# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Оформление функций в «абсолютной тьме»: код там уже разобран Ghidra, но не
# оформлен функциями, потому что статически на него никто не ссылается.
# Точки входа берём двумя способами:
#   1) адреса внутри промежутков, на которые есть ссылка типа CALL;
#   2) начало промежутка (если на него ссылок нет вовсе).
# Аргументы: lo hi (hex).
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor

lo = int(getScriptArgs()[0], 16); hi = int(getScriptArgs()[1], 16)
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
lst = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()
mon = ConsoleTaskMonitor()

spans = []
for f in fm.getFunctions(True):
    a = f.getEntryPoint().getOffset()
    if lo <= a < hi:
        spans.append((a, f.getBody().getMaxAddress().getOffset() + 1))
spans.sort()
gaps = []; cur = lo
for a, e in spans:
    if a > cur:
        gaps.append((cur, a))
    cur = max(cur, e)
if cur < hi:
    gaps.append((cur, hi))
gaps = [(a, e) for a, e in gaps if e - a >= 8]

targets = set()
for a, e in gaps:
    p = a
    while p < e:
        ad = af.getAddress(p)
        i = lst.getInstructionAt(ad)
        if i is None:
            p += 2; continue
        for r in rm.getReferencesTo(ad):
            if r.getReferenceType().isCall():
                targets.add(p); break
        p += i.getLength()
    targets.add(a)   # начало промежутка как запасная точка входа

made = fail = 0
for t in sorted(targets):
    ad = af.getAddress(t)
    if fm.getFunctionContaining(ad) is not None:
        continue
    if lst.getInstructionAt(ad) is None:
        fail += 1; continue
    if CreateFunctionCmd(ad).applyTo(currentProgram, mon):
        f = fm.getFunctionAt(ad)
        if f is not None:
            f.setComment("оформлена в проходе по «абсолютной тьме»: код был разобран, но не входил ни в одну функцию")
            made += 1
    else:
        fail += 1
print("кандидатов в точки входа: %d | создано функций: %d | неудач: %d" % (len(targets), made, fail))
