# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Создать функцию, покрывающую адрес, и декомпилировать её.
# Аргумент: адрес (hex). Идём назад, пока создание функции не удастся.
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
mon = ConsoleTaskMonitor()
dec = DecompInterface(); dec.openProgram(currentProgram)

target = int(getScriptArgs()[0], 16)
f = fm.getFunctionContaining(af.getAddress(target))
if f is None:
    for back in range(0, 4096, 2):
        a = af.getAddress(target - back)
        if listing.getInstructionAt(a) is None:
            continue
        if CreateFunctionCmd(a).applyTo(currentProgram, mon):
            f = fm.getFunctionContaining(af.getAddress(target))
            if f is not None:
                print('создана функция на 0x%x (отступ %d байт назад)' % (target - back, back))
                break
if f is None:
    print('не удалось оформить функцию вокруг 0x%x' % target)
else:
    print('=== %s @ 0x%08x (%d Б) ===' % (f.getName(), f.getEntryPoint().getOffset(),
                                          f.getBody().getNumAddresses()))
    r = dec.decompileFunction(f, 90, mon)
    print(r.getDecompiledFunction().getC() if r.decompileCompleted() else 'декомпиляция не удалась')
