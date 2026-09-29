# SPDX-License-Identifier: AGPL-3.0-or-later
# Extract each SM's log module number (1st arg to fw_log_trace*/0x8dc6c0) across
# its action functions -> buckets SMs by subsystem. Also grab known handlers'
# modules to build module->subsystem map.
# @category wil6210
# @runtime PyGhidra
import json, os, collections
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
cat=sorted(json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json'))),key=lambda x:(x['events'],x['events']*0+x['states']))
LOGS={0x8dc6c0,0x8dc748,0x8dc7a0,0x8dc8b4}  # log family (module = 1st int arg)
def modules_of(func):
    mods=collections.Counter()
    it=listing.getInstructions(func.getBody(),True)
    prev=[]
    while it.hasNext():
        ins=it.next()
        # track recent immediate loads into r0 (module arg) then a call to a log fn
        fl=ins.getFlows()
        if ins.getFlowType().isCall() and fl and fl[0].getOffset() in LOGS:
            # look back a few instructions for a small immediate (module id)
            for pins in reversed(prev[-6:]):
                got=False
                for k in range(pins.getNumOperands()):
                    for o in pins.getOpObjects(k):
                        try:
                            v=o.getValue()&0xffffffff
                            if 1<=v<=0x40:
                                mods[v]+=1; got=True; break
                        except: pass
                    if got: break
                if got: break
        prev.append(ins)
    return mods
cat_by_index=sorted(json.load(open(os.path.join(getScriptArgs()[0],'sm_catalog.json'))),key=lambda x:(x['events'],x['states']))
for i,sm in enumerate(cat_by_index):
    mods=collections.Counter()
    for a in sm['actions']:
        f=fm.getFunctionContaining(sp.getAddress(a))
        if f: mods+=modules_of(f)
    top=', '.join('0x%02x(%d)'%(m,c) for m,c in mods.most_common(3))
    print('SM%02d %dx%d  modules: %s'%(i,sm['states'],sm['events'],top or '-'))
print('\n--- module of known handlers/workers ---')
for nm2 in ('wmi_h_bf_control','wmi_h_new_sta','wmi_h_connect','connect_setup','wmi_h_discovery_start','sta_sm_post'):
    syms=st.getGlobalSymbols(nm2)
    if not syms: continue
    f=fm.getFunctionAt(syms[0].getAddress())
    if f: 
        m=modules_of(f)
        print('  %-24s %s'%(nm2, ', '.join('0x%02x'%k for k,_ in m.most_common(2)) or '-'))
