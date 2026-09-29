# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Ищем инструкции, записывающие в регистр gp (r26).
lst = currentProgram.getListing()
it = lst.getInstructions(True)
n = 0
while it.hasNext():
    i = it.next()
    s = str(i)
    if s.startswith('mov') and (' gp,' in s or s.split(',')[0].endswith(' gp')):
        print("%08x  %s" % (i.getAddress().getOffset(), s)); n += 1
    elif ' gp,' in s and not s.startswith('st') and not s.startswith('ld'):
        print("%08x  %s" % (i.getAddress().getOffset(), s)); n += 1
print("найдено записей в gp: %d" % n)
