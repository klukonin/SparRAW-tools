# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Находит функции RouterOS, патчащие board-файл, и декомпилирует их.
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

NEEDLES = ("patchBoardFileRFRegs", "brd file sector_count", "sector_offset",
           "new sectors", "wil6210-wap60g", "wil6210-lhg-span")

fm = currentProgram.getFunctionManager()
lst = currentProgram.getListing()
dec = DecompInterface(); dec.openProgram(currentProgram); mon = ConsoleTaskMonitor()

# 1) собрать строки и ссылки на них
targets = {}   # функция -> набор строк
di = lst.getDefinedData(True)
nstr = 0
while di.hasNext():
    d = di.next()
    v = d.getValue()
    if v is None: continue
    s = str(v)
    if not any(n in s for n in NEEDLES): continue
    nstr += 1
    print("STR %s  %s" % (d.getAddress(), s[:70]))
    for r in getReferencesTo(d.getAddress()):
        f = fm.getFunctionContaining(r.getFromAddress())
        if f:
            targets.setdefault(f, set()).add(s[:40])
            print("    <- %s  в %s" % (r.getFromAddress(), f.getName()))
        else:
            print("    <- %s  (вне функции)" % r.getFromAddress())
print("\nстрок найдено: %d, функций-кандидатов: %d\n" % (nstr, len(targets)))

# 2) декомпилировать кандидатов
for f, ss in sorted(targets.items(), key=lambda kv: kv[0].getEntryPoint().getOffset()):
    print("\n########## %s @ %s   строки: %s" % (f.getName(), f.getEntryPoint(), sorted(ss)))
    r = dec.decompileFunction(f, 120, mon)
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split("\n"):
            print(l[:120])
    else:
        print("  (декомпиляция не удалась)")
