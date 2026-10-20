# SPDX-License-Identifier: AGPL-3.0-or-later
# Декомпиляция функций по списку адресов (аргумент - файл с hex-адресами)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import java.io as jio
args = getScriptArgs()
addrs = [l.strip() for l in open(args[0]) if l.strip()]
di = DecompInterface(); di.openProgram(currentProgram)
fm = currentProgram.getFunctionManager(); mon = ConsoleTaskMonitor()
for a in addrs:
    ad = currentProgram.getAddressFactory().getAddress(a)
    f = fm.getFunctionContaining(ad)
    if f is None:
        print("=== %s НЕТ ФУНКЦИИ ===" % a); continue
    r = di.decompileFunction(f, 90, mon)
    print("=== %s %s (%d Б) ===" % (a, f.getName(), f.getBody().getNumAddresses()))
    print(r.getDecompiledFunction().getC() if r.decompileCompleted() else "!! %s" % r.getErrorMessage())
