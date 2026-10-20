# SPDX-License-Identifier: AGPL-3.0-or-later
# Выгрузка рёбер графа вызовов: CALL <откуда> <куда>
from ghidra.program.model.symbol import RefType
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()
out = []
for f in fm.getFunctions(True):
    src = f.getEntryPoint().getOffset()
    body = f.getBody()
    for addr in rm.getReferenceSourceIterator(body, True):
        for r in rm.getReferencesFrom(addr):
            if r.getReferenceType().isCall():
                out.append("CALL %06x %06x" % (src, r.getToAddress().getOffset()))
print("EDGES %d" % len(out))
for l in out: print(l)
