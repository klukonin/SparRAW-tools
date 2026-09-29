# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Переименование функций по файлу "адрес имя # обоснование".
# Меняет имя только если текущее FUN_* или uclog_* (автоимя из лог-строки).
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
ok = skip = miss = 0
for line in open(getScriptArgs()[0]):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    parts = line.split(None, 2)
    addr, name = int(parts[0], 16), parts[1]
    why = parts[2].lstrip('# ') if len(parts) > 2 else ''
    f = fm.getFunctionAt(af.getAddress(addr))
    if f is None:
        print("НЕТ ФУНКЦИИ на 0x%06x" % addr); miss += 1; continue
    cur = f.getName()
    if not (cur.startswith('FUN_') or cur.startswith('uclog_') or cur.startswith('thunk_')):
        print("пропуск 0x%06x: уже назван %s" % (addr, cur)); skip += 1; continue
    f.setName(name, SourceType.USER_DEFINED)
    if why:
        f.setComment(why)
    ok += 1
print("переименовано: %d, пропущено: %d, не найдено: %d" % (ok, skip, miss))
