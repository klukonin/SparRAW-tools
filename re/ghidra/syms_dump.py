# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Выгрузить символы проекта в формате SYMS-*.txt: адрес, размер, источник, имя.
fm = currentProgram.getFunctionManager()
funcs = list(fm.getFunctions(True))
named = [f for f in funcs if not f.getName().startswith('FUN_')]
print('FUNCS %d NAMED %d' % (len(funcs), len(named)))
for f in funcs:
    src = 'auto' if f.getName().startswith('FUN_') else 'user'
    print('SYM 0x%08x %6d %s %s' % (f.getEntryPoint().getOffset(),
                                    f.getBody().getNumAddresses(), src, f.getName()))
