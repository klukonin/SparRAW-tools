# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Поднять ucode-сегмент: дизассемблировать от известных точек входа с
# прослеживанием потока, затем итеративно создавать функции в целях вызовов.
# Аргументы: список seed-адресов (hex). МЕНЯЕТ ПРОЕКТ.
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType

mon = ConsoleTaskMonitor()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()

seeds = [int(a, 16) for a in getScriptArgs()]
print('seed-адресов: %d' % len(seeds))

def disas(addrs):
    n = 0
    for a in addrs:
        ad = af.getAddress(a)
        if listing.getInstructionContaining(ad) is None:
            listing.clearCodeUnits(ad, ad.add(3), False)
            if DisassembleCommand(ad, None, True).applyTo(currentProgram, mon):
                n += 1
    return n

def call_targets():
    t = set()
    it = listing.getInstructions(True)
    while it.hasNext():
        for ref in it.next().getReferencesFrom():
            if ref.getReferenceType() in (RefType.UNCONDITIONAL_CALL,
                                          RefType.CONDITIONAL_CALL):
                t.add(ref.getToAddress().getOffset())
    return t

total = disas(seeds)
for rnd in range(6):
    tg = call_targets()
    new = disas(tg)
    made = 0
    for a in tg:
        ad = af.getAddress(a)
        if fm.getFunctionAt(ad) is None and listing.getInstructionAt(ad) is not None:
            if CreateFunctionCmd(ad).applyTo(currentProgram, mon):
                made += 1
    print('  круг %d: целей %d, новых дизасм %d, функций создано %d, всего функций %d'
          % (rnd, len(tg), new, made, fm.getFunctionCount()))
    if new == 0 and made == 0:
        break
print('итого функций в ucode: %d' % fm.getFunctionCount())
