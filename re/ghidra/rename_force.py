# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Переименование БЕЗ проверки текущего имени (уточнение уже данного имени).
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
ok = 0
for line in open(getScriptArgs()[0]):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    p = line.split(None, 2)
    f = fm.getFunctionAt(af.getAddress(int(p[0], 16)))
    if f is None:
        print("НЕТ ФУНКЦИИ на %s" % p[0]); continue
    f.setName(p[1], SourceType.USER_DEFINED)
    if len(p) > 2:
        f.setComment(p[2].lstrip('# '))
    ok += 1
print("уточнено имён: %d" % ok)
