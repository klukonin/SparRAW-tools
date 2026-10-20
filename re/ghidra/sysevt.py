# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mon=ConsoleTaskMonitor(); mem=currentProgram.getMemory()
ref=currentProgram.getReferenceManager(); dec=DecompInterface(); dec.openProgram(currentProgram)
def rd(off,n=160):
    o=bytearray()
    for i in range(n):
        try: v=mem.getByte(sp.getAddress(off+i))&0xff
        except Exception: return None
        if v==0: break
        o.append(v)
    s=o.decode('latin1')
    return s if s and all(32<=ord(c)<127 for c in s) else None
pat=re.compile(r'(?:UNK|DAT|s)_ram_(01[0-9a-f]{6})')
sub=lambda l: pat.sub(lambda m:'"%s"'%(rd(int(m.group(1),16)) or m.group(0)),l)
for off in (0x8c263c, 0x8df50c):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('\n0x%06x — вне функций'%off); continue
    us=set()
    for r in ref.getReferencesTo(f.getEntryPoint()):
        cf=fm.getFunctionContaining(r.getFromAddress())
        if cf: us.add('%s@0x%06x'%(cf.getName().replace('FUN_ram_',''),cf.getEntryPoint().getOffset()))
    res=dec.decompileFunction(f,60,mon)
    print('\n===== 0x%06x %s (%dБ)  зовут: %s ====='%(off,f.getName(),
          f.getBody().getNumAddresses(),', '.join(sorted(us))[:130] or '-'))
    if res and res.decompileCompleted():
        for l in res.getDecompiledFunction().getC().split('\n')[:30]: print('  '+sub(l)[:145])
