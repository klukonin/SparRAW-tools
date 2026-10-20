# SPDX-License-Identifier: AGPL-3.0-or-later
# Profile each SM: init caller + named callees of its action functions +
# hardware (RGF) touches -> infer role.
# @category wil6210
# @runtime PyGhidra
import json, os, collections
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); ref=currentProgram.getReferenceManager()
mon=ConsoleTaskMonitor()
cat=sorted(json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json'))),key=lambda x:(x['events'],x['states']))
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else None
def callees_named(f):
    out=set()
    for c in f.getCalledFunctions(mon):
        n=c.getName()
        if not n.startswith(('FUN_','sm%02d'%0)) and not n.startswith('thunk'):
            out.add(n)
    return out
def scalars_touch_rgf(f):
    regs=set()
    body=f.getBody()
    it=currentProgram.getListing().getInstructions(body,True)
    while it.hasNext():
        ins=it.next()
        for k in range(ins.getNumOperands()):
            for o in ins.getOpObjects(k):
                try:
                    v=o.getValue()&0xffffffff
                    if 0x880000<=v<0x8a0000: regs.add(v)   # RGF/hardware
                except: pass
    return regs
for i,sm in enumerate(cat):
    # init caller
    isyms=st.getGlobalSymbols('sm%02d_init'%i)
    callers=set()
    if isyms:
        for r in ref.getReferencesTo(isyms[0].getAddress()):
            c=nm(r.getFromAddress())
            if c and c!='sm%02d_init'%i: callers.add(c)
    named=set(); regs=set()
    for a in sm['actions']:
        f=fm.getFunctionContaining(sp.getAddress(a))
        if f:
            named|=callees_named(f); regs|=scalars_touch_rgf(f)
    named={n for n in named if not n.startswith('sm%02d'%i)}
    print('SM%02d %dx%d | init<-%s | calls: %s | rgf: %s'%(
        i,sm['states'],sm['events'],
        ','.join(sorted(callers)[:3]) or '?',
        ', '.join(sorted(named)[:10]) or '-',
        ','.join('0x%x'%r for r in sorted(regs)[:5]) or '-'))
