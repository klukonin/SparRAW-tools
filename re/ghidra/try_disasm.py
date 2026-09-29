# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Пробное дизассемблирование диапазона с оценкой качества.
# Аргументы: start end (hex). НЕ создаёт функций — только разбирает и считает.
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
a0 = int(getScriptArgs()[0], 16); a1 = int(getScriptArgs()[1], 16)
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
lst = currentProgram.getListing()
mon = ConsoleTaskMonitor()
DisassembleCommand(af.getAddress(a0), AddressSet(af.getAddress(a0), af.getAddress(a1 - 1)), True).applyTo(currentProgram, mon)
a = af.getAddress(a0); n = 0; bad = 0; cov = 0; rets = 0
while a.getOffset() < a1:
    i = lst.getInstructionAt(a)
    if i is None:
        bad += 2; a = a.add(2); continue
    s = str(i)
    if s.startswith('j') or s.startswith('rtie'):
        rets += 1
    n += 1; cov += i.getLength(); a = a.add(i.getLength())
print("РАЗБОР 0x%06x..0x%06x: инструкций %d, разобрано %d Б, не разобрано %d Б, переходов/возвратов %d"
      % (a0, a1, n, cov, bad, rets))
