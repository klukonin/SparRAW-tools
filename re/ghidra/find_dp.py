# SPDX-License-Identifier: AGPL-3.0-or-later
# Locate handlers for datapath/PS/BA commands by their command-id constants.
# @category wil6210
# @runtime PyGhidra
import collections
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing(); mem=currentProgram.getMemory()
TARGET={0x821:'vring_cfg',0x822:'bcast_vring_cfg',0x823:'ring_ba_en',0x824:'ring_ba_dis',
        0x825:'addba_resp',0x826:'delba',0x913:'power_mgmt_cfg',0x91c:'ps_dev_profile',
        0x9c2:'tx_desc_ring_add',0x9c3:'rx_desc_ring_add'}
def scalars(ins):
    out=[]
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try: out.append(o.getValue()&0xffffffff)
            except: pass
    return out
def nm(off):
    a=sp.getAddress(off)
    f=fm.getFunctionContaining(a); return f.getName() if f else '(top)'
# find each id-immediate site and the containing function + nearby call
sites=collections.defaultdict(list)
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    o=ins.getAddress().getOffset()
    if not (0x8c0000<=o<0x900000): continue
    for v in scalars(ins):
        if v in TARGET:
            f=fm.getFunctionContaining(ins.getAddress())
            sites[v].append((o, f.getName() if f else '(top)'))
            break
for v,lst in sorted(sites.items()):
    fns=collections.Counter(fn for _,fn in lst)
    print('0x%04x %-16s in: %s'%(v,TARGET[v],', '.join('%s(%d)'%(f,c) for f,c in fns.most_common(3))))
print('\nids not found:', ', '.join('0x%04x'%v for v in TARGET if v not in sites))
