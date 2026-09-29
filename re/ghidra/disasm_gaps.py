# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Разбор «абсолютной тьмы»: байтов, которые не входят ни в одну функцию и не
# разобраны как инструкции. Ghidra до них не дотягивается, потому что статически
# на них никто не ссылается (вызов идёт через таблицы в ОЗУ или косвенно).
# Аргументы: lo hi (hex) - границы сегмента.
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet

lo = int(getScriptArgs()[0], 16); hi = int(getScriptArgs()[1], 16)
MIN_GAP = 16
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
lst = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
mon = ConsoleTaskMonitor()

# собрать промежутки, не покрытые функциями
spans = []
for f in fm.getFunctions(True):
    a = f.getEntryPoint().getOffset()
    if lo <= a < hi:
        b = f.getBody()
        spans.append((a, b.getMaxAddress().getOffset() + 1))
spans.sort()
gaps = []; cur = lo
for a, e in spans:
    if a > cur:
        gaps.append((cur, a))
    cur = max(cur, e)
if cur < hi:
    gaps.append((cur, hi))
gaps = [(a, e) for a, e in gaps if e - a >= MIN_GAP]
print("промежутков вне функций: %d, суммарно %d Б" % (len(gaps), sum(e - a for a, e in gaps)))

done = 0
for a, e in gaps:
    # разбираем только то, что ещё не разобрано
    start = af.getAddress(a)
    if lst.getInstructionAt(start) is None and lst.getDataAt(start) is None:
        DisassembleCommand(start, AddressSet(start, af.getAddress(e - 1)), True).applyTo(currentProgram, mon)
        done += 1
print("запущен разбор в %d промежутках" % done)

# оценка: сколько байт в промежутках теперь покрыто инструкциями
cov = bad = 0
for a, e in gaps:
    p = a
    while p < e:
        i = lst.getInstructionAt(af.getAddress(p))
        if i is None:
            bad += 2; p += 2
        else:
            cov += i.getLength(); p += i.getLength()
print("в промежутках: разобрано %d Б, осталось неразобранным %d Б" % (cov, bad))
