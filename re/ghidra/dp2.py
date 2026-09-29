# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import collections,json,os
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
cmds=json.load(open('/tmp/wmi_cmds_real.json'))
id2name={int(v):k for k,v in cmds.items()}
def scalars(ins):
    out=[]
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try: out.append(o.getValue()&0xffffffff)
            except: pass
    return out
# 1) datapath ids in ucode?
TARGET={0x821,0x822,0x823,0x824,0x825,0x826,0x913,0x91c,0x9c2,0x9c3,0x16,0x17}
uc=set()
it=listing.getInstructions(sp.getAddress(0x920000),True)
while it.hasNext():
    ins=it.next()
    if ins.getAddress().getOffset()>=0x93c608: break
    for v in scalars(ins):
        if v in TARGET: uc.add(v)
print('datapath/PS/key ids present in UCODE:', ', '.join('0x%03x'%v for v in sorted(uc)) or 'NONE')
# 2) full set of command ids handled by the mgmt dispatcher (0x8de070..0x8dec66)
TAIL=0x8dec72; lo,hi=0x8de070,0x8dec66
handled=set()
ins=listing.getInstructionAt(sp.getAddress(lo))
while ins is not None and ins.getAddress().getOffset()<=hi:
    for v in scalars(ins):
        if v in id2name: handled.add(v)
    ins=ins.getNext()
print('\ncommand ids handled by mgmt dispatcher (%d):'%len(handled))
print('  '+', '.join('0x%03x'%v for v in sorted(handled)))
# which whole groups are absent
groups=collections.Counter(v>>8 for v in id2name)
hgroups=collections.Counter(v>>8 for v in handled)
print('\nby group (handled/total):')
for g in sorted(groups): print('  0x%02xxx: %d/%d'%(g,hgroups.get(g,0),groups[g]))
