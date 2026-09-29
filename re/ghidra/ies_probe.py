# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mon=ConsoleTaskMonitor()
mem=currentProgram.getMemory(); listing=currentProgram.getListing()
ref=currentProgram.getReferenceManager()
dec=DecompInterface(); dec.openProgram(currentProgram)
def rd(off,n=150):
    o=bytearray()
    for i in range(n):
        try: v=mem.getByte(sp.getAddress(off+i))&0xff
        except Exception: return None
        if v==0: break
        o.append(v)
    s=o.decode('latin1')
    return s if s and all(32<=ord(c)<127 for c in s) else None
pat=re.compile(r'(?:UNK|DAT|s)_ram_(01[0-9a-f]{6})')
sub=lambda l: pat.sub(lambda m:'"%s"'%(rd(int(m.group(1),16)) or m.group(0)), l)

print('=== семейство 0x8ef7xx: размеры и пользователи ===')
for off in (0x8ef740,0x8ef7b8,0x8ef804,0x8ef84c,0x8ef864,0x8ef87c,0x8ef898,0x8ef8dc):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('  0x%06x — нет функции'%off); continue
    us=set()
    for r in ref.getReferencesTo(f.getEntryPoint()):
        cf=fm.getFunctionContaining(r.getFromAddress())
        if cf: us.add(cf.getEntryPoint().getOffset())
    print('  0x%06x %-28s %4d Б  пользователей %d'%(off,f.getName(),f.getBody().getNumAddresses(),len(us)))

for off in (0x8ef7b8, 0x8ecc40):
    f=fm.getFunctionContaining(sp.getAddress(off))
    r=dec.decompileFunction(f,60,mon)
    print('\n===== 0x%06x (%d Б) ====='%(off,f.getBody().getNumAddresses()))
    if r and r.decompileCompleted():
        for l in r.getDecompiledFunction().getC().split('\n')[:40]: print('  '+sub(l)[:140])
