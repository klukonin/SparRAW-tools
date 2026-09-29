# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Декомпиляция функций по адресам из аргументов: decomp_args.py 0x8c6d68 0x8e7418 ...
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
dec = DecompInterface(); dec.openProgram(currentProgram); mon = ConsoleTaskMonitor()
for arg in getScriptArgs():
    off = int(arg, 16)
    f = fm.getFunctionContaining(sp.getAddress(off))
    if f is None:
        print('=== %s: функции нет ===' % arg); continue
    print('=== %s @ 0x%08x (%d Б) ===' % (f.getName(), f.getEntryPoint().getOffset(),
                                          f.getBody().getNumAddresses()))
    r = dec.decompileFunction(f, 60, mon)
    print(r.getDecompiledFunction().getC() if r.decompileCompleted() else 'декомпиляция не удалась')
