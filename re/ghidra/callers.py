# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Кто вызывает заданные адреса. Аргументы: список адресов (hex).
from ghidra.program.model.symbol import RefType
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()
for arg in getScriptArgs():
    a = af.getAddress(int(arg, 16))
    f = fm.getFunctionAt(a)
    print('=== %s @ %s ===' % (f.getName() if f else '?', arg))
    n = 0
    for ref in rm.getReferencesTo(a):
        src = ref.getFromAddress()
        cf = fm.getFunctionContaining(src)
        print('   из %s  %s  (%s)' % (src, ref.getReferenceType(),
                                      ('%s @0x%x' % (cf.getName(), cf.getEntryPoint().getOffset())) if cf else 'вне функций'))
        n += 1
    if not n:
        print('   ссылок не найдено')
