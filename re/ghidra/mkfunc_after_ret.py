# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Второй проход по «абсолютной тьме»: точка входа = инструкция, следующая за
# концом функции. Конец в ARC — это j blink / j.d blink либо переход в
# milli-code эпилог (0x8c02d4..0x8c0344 в fw, 0x920224..0x9202a0 в ucode).
# Аргументы: lo hi (hex).
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor
import re

lo = int(getScriptArgs()[0], 16); hi = int(getScriptArgs()[1], 16)
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
lst = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
mon = ConsoleTaskMonitor()

EPI_FW = (0x8c02d4, 0x8c0348)
EPI_UC = (0x920224, 0x9202a4)

def is_terminator(i):
    s = str(i)
    if 'blink' in s and (s.startswith('j') or s.startswith('j_s')):
        return True
    m = re.match(r'^b(?:_s)?(?:\.d)?\s+0x([0-9a-f]+)', s)
    if m:
        t = int(m.group(1), 16)
        if EPI_FW[0] <= t < EPI_FW[1] or EPI_UC[0] <= t < EPI_UC[1]:
            return True
    return False

for rnd in range(4):
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

    entries = set()
    for a, e in gaps:
        entries.add(a)
        p = a; prev_term = False
        while p < e:
            i = lst.getInstructionAt(af.getAddress(p))
            if i is None:
                p += 2; prev_term = False; continue
            if prev_term:
                entries.add(p); prev_term = False
            if is_terminator(i):
                prev_term = True
                p += i.getLength()
                # пропускаем слот задержки
                d = lst.getInstructionAt(af.getAddress(p))
                if d is not None and str(i).find('.d') >= 0:
                    p += d.getLength()
                continue
            p += i.getLength()

    made = 0
    for t in sorted(entries):
        ad = af.getAddress(t)
        if fm.getFunctionContaining(ad) is not None:
            continue
        if lst.getInstructionAt(ad) is None:
            continue
        if CreateFunctionCmd(ad).applyTo(currentProgram, mon):
            f = fm.getFunctionAt(ad)
            if f is not None:
                f.setComment("оформлена по границе «после возврата» в проходе по «абсолютной тьме»")
                made += 1
    print("круг %d: кандидатов %d, создано %d" % (rnd + 1, len(entries), made))
    if made == 0:
        break
