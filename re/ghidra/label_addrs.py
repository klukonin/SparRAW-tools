# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Метки на адресах, которые являются ТОЧКАМИ ВХОДА внутрь существующей функции
# (milli-code ARC: один общий блок, вход с разным числом спасаемых регистров).
# Дробить такой блок на функции нельзя - метки сохраняют знание, не ломая разметку.
from ghidra.program.model.symbol import SourceType
st = currentProgram.getSymbolTable()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
ok = 0
for line in open(getScriptArgs()[0]):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    p = line.split(None, 2)
    a = af.getAddress(int(p[0], 16))
    st.createLabel(a, p[1], SourceType.USER_DEFINED)
    ok += 1
print("поставлено меток: %d" % ok)
