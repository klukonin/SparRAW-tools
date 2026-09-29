# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Массовое создание функций по адресам, найденным в ЖИВОМ дампе ОЗУ
# (таблицы диспетчеризации ucode заполняются в рантайме и в образе отсутствуют).
# Аргумент: файл с hex-адресами.
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
lst = currentProgram.getListing()
mon = ConsoleTaskMonitor()
addrs = [int(l, 16) for l in open(getScriptArgs()[0]) if l.strip()]
made = dis = fail = 0
for v in addrs:
    a = af.getAddress(v)
    if fm.getFunctionContaining(a) is not None:
        continue
    # НЕ дизассемблируем принудительно: единственный надёжный признак того, что
    # адрес - код, а не совпавшее целое число в данных, это уже разобранная
    # Ghidra инструкция на нём (проверено на 43 адресах таблиц диспетчеризации).
    if lst.getInstructionAt(a) is None:
        fail += 1
        continue
    if CreateFunctionCmd(a).applyTo(currentProgram, mon):
        f = fm.getFunctionAt(a)
        if f is not None:
            f.setComment("точка входа найдена в живом дампе ОЗУ (таблица диспетчеризации)")
            made += 1
    else:
        fail += 1
print("создано функций: %d (из них потребовали дизассемблирования: %d), неудач: %d" % (made, dis, fail))
