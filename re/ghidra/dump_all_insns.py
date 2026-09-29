# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Полная выгрузка инструкций образа: адрес, длина, текст.
# Нужна для пересборки прошивки из собственного дерева исходников.
lst = currentProgram.getListing()
it = lst.getInstructions(True)
n = 0
out = []
while it.hasNext():
    i = it.next()
    a = i.getAddress().getOffset()
    out.append("I %06x %d %s" % (a, i.getLength(), str(i)))
    n += 1
print("INSNS %d" % n)
for l in out:
    print(l)
