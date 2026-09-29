# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import re, json, os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
cat=sorted(json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json'))),key=lambda x:(x['events'],x['states']))
desc2sm={sm['desc']-0x100000:i for i,sm in enumerate(cat)}
smi=set()
for i in range(15):
    s=st.getGlobalSymbols('sm%02d_init'%i)
    if s: smi.add((s[0].getAddress().getOffset(),i))
s0=st.getGlobalSymbols('sm_init'); sm_init_ep=s0[0].getAddress()
# find functions calling >=2 smNN_init  OR calling smNN_init with +0x104/+0x80/+0x1d0
seen=set()
for ep,idx in smi:
    f=fm.getFunctionAt(sp.getAddress(ep))
    for r in ref.getReferencesTo(f.getEntryPoint()):
        cf=fm.getFunctionContaining(r.getFromAddress())
        if not cf or cf.getEntryPoint().getOffset() in seen: continue
        rr=dec.decompileFunction(cf,25,mon)
        if not (rr and rr.decompileCompleted()): continue
        c=rr.getDecompiledFunction().getC()
        inits=[l.strip() for l in c.split('\n') if re.search(r'sm\d\d_init\(',l)]
        if len(inits)>=2 or any('0x104' in l for l in inits):
            seen.add(cf.getEntryPoint().getOffset())
            print('\n### %s @0x%06x (station/vif ctor?)'%(cf.getName(),cf.getEntryPoint().getOffset()))
            for l in inits: print('  '+l[:88])
