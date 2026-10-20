# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Поднять область ucode: дизассемблировать с указанного адреса по потоку,
# оформить функции в целях переходов/вызовов и декомпилировать ту,
# что содержит адрес интереса. Аргументы: <старт> <конец> <адрес_интереса>
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType

af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
mon = ConsoleTaskMonitor()

start, end, want = [int(x, 16) for x in getScriptArgs()[:3]]

n = 0
a = start
while a < end:
    ad = af.getAddress(a)
    if listing.getInstructionContaining(ad) is None:
        listing.clearCodeUnits(ad, ad.add(3), False)
        if DisassembleCommand(ad, None, True).applyTo(currentProgram, mon):
            n += 1
    a += 2
print('запусков дизассемблера: %d' % n)

# функции в целях переходов внутри области
targets = set()
it = listing.getInstructions(af.getAddress(start), True)
while it.hasNext():
    ins = it.next()
    if ins.getAddress().getOffset() > end:
        break
    for ref in ins.getReferencesFrom():
        if ref.getReferenceType() in (RefType.UNCONDITIONAL_CALL, RefType.CONDITIONAL_CALL,
                                      RefType.UNCONDITIONAL_JUMP, RefType.CONDITIONAL_JUMP):
            targets.add(ref.getToAddress())
made = 0
for t in sorted(targets):
    if fm.getFunctionAt(t) is None and listing.getInstructionAt(t) is not None:
        if CreateFunctionCmd(t).applyTo(currentProgram, mon):
            made += 1
print('оформлено функций: %d (всего %d)' % (made, fm.getFunctionCount()))

dec = DecompInterface(); dec.openProgram(currentProgram)
f = fm.getFunctionContaining(af.getAddress(want))
if f is None:
    for back in range(0, 2048, 2):
        ad = af.getAddress(want - back)
        if listing.getInstructionAt(ad) and CreateFunctionCmd(ad).applyTo(currentProgram, mon):
            f = fm.getFunctionContaining(af.getAddress(want))
            if f:
                break
if f is None:
    print('функцию вокруг 0x%x оформить не удалось' % want)
else:
    print('=== %s @ 0x%08x (%d Б) ===' % (f.getName(), f.getEntryPoint().getOffset(),
                                          f.getBody().getNumAddresses()))
    r = dec.decompileFunction(f, 90, mon)
    print(r.getDecompiledFunction().getC() if r.decompileCompleted() else 'декомпиляция не удалась')
