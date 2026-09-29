# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Обработчики AW/DTI оказались разрезаны на две функции (22 Б + 130 Б):
# настоящий вход взят из таблицы переходов, снятой с железа. Сшиваем.
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
mon = ConsoleTaskMonitor()

PAIRS = [(0x931078, 0x93108e, "bi_ap_mon__aw_event",
          "вход из таблицы переходов 0x800adc (событие 3). Пишет 0xcaf220 в кольцо "
          "регистров MAC, счётчик AW 0x801e1e. Проверено на железе: при bcon_kind==2 не вызывается."),
         (0x931270, 0x931286, "bi_ap_mon__dti_event",
          "вход из таблицы переходов 0x800adc (событие 2). Пишет 0xcaf110 в кольцо "
          "регистров MAC, счётчик DTI 0x801e1c.")]

for entry, bogus, name, why in PAIRS:
    for a in (bogus, entry):
        f = fm.getFunctionAt(af.getAddress(a))
        if f is not None:
            fm.removeFunction(af.getAddress(a))
    if CreateFunctionCmd(af.getAddress(entry)).applyTo(currentProgram, mon):
        f = fm.getFunctionAt(af.getAddress(entry))
        f.setName(name, SourceType.USER_DEFINED)
        f.setComment(why)
        print("0x%06x -> %s, тело %d Б" % (entry, name, f.getBody().getNumAddresses()))
    else:
        print("НЕ УДАЛОСЬ пересобрать функцию на 0x%06x" % entry)
