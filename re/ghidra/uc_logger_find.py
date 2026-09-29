# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Найти функцию-логгер ucode: для каждого места, где грузится указатель на
# строку (limm 0x01000000|offset), посмотреть ближайший последующий вызов.
# Самая частая цель и есть логгер. Аргумент: TSV "адрес<TAB>строка".
from collections import Counter
from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()

sites = [int(l.split('\t')[0], 16) for l in open(getScriptArgs()[0])]
tgt = Counter()
for a in sites:
    ins = listing.getInstructionContaining(af.getAddress(a))
    n = 0
    while ins is not None and n < 12:
        for ref in ins.getReferencesFrom():
            if ref.getReferenceType() in (RefType.UNCONDITIONAL_CALL,
                                          RefType.CONDITIONAL_CALL):
                tgt[ref.getToAddress().getOffset()] += 1
                n = 99
                break
        if n == 99:
            break
        ins = ins.getNext()
        n += 1
print('мест со строками: %d' % len(sites))
for a, c in tgt.most_common(6):
    f = fm.getFunctionAt(af.getAddress(a))
    print('  0x%06x  вызовов %3d  %s' % (a, c, f.getName() if f else '(не функция)'))
