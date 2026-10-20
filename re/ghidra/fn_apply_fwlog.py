# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Применить к проекту fw4100 имена, выведенные из ЛОГ-СТРОК прошивки
# (таблица строк = запись 101 образа MikroTik; ссылки в коде — limm 0x01000000|offset).
# Аргумент: FN-NAMES-FROM-FWLOG.txt
# МЕНЯЕТ ПРОЕКТ, но только там, где имя сейчас FUN_*; доказательство кладётся
# в plate comment функции.
from collections import Counter
from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
path = getScriptArgs()[0]

rows = []
for line in open(path):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    parts = line.split(None, 3)
    if len(parts) < 3 or not parts[0].startswith('0x'):
        continue
    addr = int(parts[0], 16)
    name = parts[2]
    ev = parts[3].split('|', 1)[1].strip() if len(parts) > 3 and '|' in parts[3] else ''
    rows.append((addr, name, ev))

# одно и то же имя у многих функций = это тег/файл, а не имя функции
cnt = Counter(n for _, n, _ in rows)
GENERIC = {n for n, c in cnt.items() if c > 2}
print('пропускаю неспецифичные имена (встречаются >2 раз): %d' % len(GENERIC))

applied = skipped = missing = 0
for addr, name, ev in rows:
    if name in GENERIC:
        skipped += 1
        continue
    a = af.getAddress(addr)
    f = fm.getFunctionAt(a)
    if f is None:
        f = fm.getFunctionContaining(a)
    if f is None:
        missing += 1
        continue
    if not f.getName().startswith('FUN_'):
        skipped += 1
        continue
    f.setName('fwlog_' + name, SourceType.USER_DEFINED)
    if ev:
        old = f.getComment() or ''
        f.setComment((old + '\n' if old else '') + 'из лог-строки прошивки: ' + ev)
    applied += 1

print('назначено имён: %d | пропущено: %d | функция не найдена: %d' % (applied, skipped, missing))
