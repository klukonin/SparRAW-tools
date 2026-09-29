# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Все проверки битов регистра состояния r42 (и соседних r40/r43/r45/r47/r51/r53)
# в ucode: именно по ним код ждёт аппаратные события.
import re
lst = currentProgram.getListing()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
it = lst.getInstructions(af.getAddress(0x920000), True)
pat = re.compile(r'\b(r4[0-9]|r5[0-9])\b')
rows = []
while it.hasNext():
    i = it.next()
    a = i.getAddress().getOffset()
    if a >= 0x9380c4:
        break
    s = str(i)
    if not pat.search(s):
        continue
    if s.startswith(('bbit', 'btst', 'and', 'tst', 'brne', 'breq', 'bmsk')):
        rows.append("R42 %06x %s" % (a, s))
print("R42COUNT %d" % len(rows))
for r in rows:
    print(r)
