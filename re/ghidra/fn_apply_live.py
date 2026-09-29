# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Применить имена функций, исполнение которых ДОКАЗАНО живой трассировкой.
# Аргумент: FN-NAMES-LIVE.txt. МЕНЯЕТ ПРОЕКТ, только там, где имя FUN_*.
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
applied = skipped = 0
for line in open(getScriptArgs()[0]):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    p = line.split(None, 3)
    if len(p) < 3 or not p[0].startswith('0x'):
        continue
    f = fm.getFunctionContaining(af.getAddress(int(p[0], 16)))
    if f is None or not f.getName().startswith('FUN_'):
        skipped += 1
        continue
    f.setName('live_' + p[2], SourceType.USER_DEFINED)
    ev = p[3].lstrip('# ').strip() if len(p) > 3 else ''
    old = f.getComment() or ''
    f.setComment((old + '\n' if old else '') +
                 'ИСПОЛНЕНИЕ ДОКАЗАНО на железе (лог прошивки): ' + ev)
    applied += 1
print('назначено имён: %d | пропущено: %d' % (applied, skipped))
