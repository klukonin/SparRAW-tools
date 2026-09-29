# SPDX-License-Identifier: AGPL-3.0-or-later
# Refine SM roles: per-SM decompile init + aggregate action callees + RGF sub-regions.
# @category wil6210
# @runtime PyGhidra
import json, os, collections
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
cat=sorted(json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json'))),key=lambda x:(x['events'],x['states']))
def rgf_regions(f):
    reg=set()
    it=listing.getInstructions(f.getBody(),True)
    while it.hasNext():
        ins=it.next()
        for k in range(ins.getNumOperands()):
            for o in ins.getOpObjects(k):
                try:
                    v=o.getValue()&0xffffffff
                    if 0x880000<=v<0x8a0000: reg.add(v&0xffff00)
                except: pass
    return reg
for i,sm in enumerate(cat):
    isyms=st.getGlobalSymbols('sm%02d_init'%i)
    initline=''
    if isyms:
        f=fm.getFunctionAt(isyms[0].getAddress())
        if f:
            r=dec.decompileFunction(f,20,mon)
            if r and r.decompileCompleted():
                c=r.getDecompiledFunction().getC()
                # extract the sm_init(obj,&desc) + initial event/state hints
                for l in c.split('\n'):
                    if 'sm_post_event' in l or 'sm_init' in l or '0x8' in l and '=' in l:
                        initline=l.strip()[:80]; break
    named=collections.Counter(); rgf=set(); crosssm=set()
    for a in sm['actions']:
        f=fm.getFunctionContaining(sp.getAddress(a))
        if not f: continue
        rgf|=rgf_regions(f)
        for c in f.getCalledFunctions(mon):
            n=c.getName()
            if n.startswith(('wmi_','sta_','fw_find','fw_post','connect_')): named[n]+=1
            if n.startswith(('sm_init','sm_post')): crosssm.add(n)
    top=', '.join('%s(%d)'%(n,c) for n,c in named.most_common(6))
    print('SM%02d %dx%d | rgf:%s | actions_call: %s'%(
        i,sm['states'],sm['events'],
        ','.join('0x%05x'%r for r in sorted(rgf)) or '-', top or '-'))
