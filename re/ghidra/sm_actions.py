# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import json, os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
cat={('%dx%d'%(x['states'],x['events'])):x for x in json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json')))}
def nm(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: return f.getName()
    ss=st.getSymbols(sp.getAddress(off)); return ss[0].getName() if ss else 'FUN_%06x'%off
import sys
which=sys.argv  # unused
# SM09 (7x8) and SM11 (4x10) and SM02 (3x4) by dims
for tag in ('7x8','4x10','3x4'):
    sm=cat[tag]
    print('\n########## SM %s  desc 0x%06x  actions=%d ##########'%(tag,sm['desc'],len(sm['actions'])))
    for a in sm['actions'][:6]:
        f=fm.getFunctionContaining(sp.getAddress(a))
        if not f: continue
        callees=sorted(set(nm(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
        print('--- action %s (%d B) calls: %s'%(nm(a),f.getBody().getNumAddresses(),', '.join(callees[:10])))
        r=dec.decompileFunction(f,25,mon)
        if r and r.decompileCompleted():
            for l in r.getDecompiledFunction().getC().split('\n')[:16]:
                s=l.strip()
                if s and not s.startswith(('undefined','int ','uint ','void','{','}','/*')): print('    '+s[:96])
