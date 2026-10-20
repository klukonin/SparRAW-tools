# SPDX-License-Identifier: AGPL-3.0-or-later
# MLME structural sweep: enumerate functions by log module (0x16 build, 0x27 tx,
# and neighbours), map the mgmt-frame builder/tx/rx skeleton.
# @category wil6210
# @runtime PyGhidra
import collections
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
LOGS={0x8dc6c0,0x8dc748,0x8dc7a0,0x8dc8b4}
# per-function dominant module + call graph among mgmt funcs
func_mods=collections.defaultdict(collections.Counter)
it=listing.getInstructions(True); prev=[]
while it.hasNext():
    ins=it.next(); fl=ins.getFlows()
    if ins.getFlowType().isCall() and fl and fl[0].getOffset() in LOGS:
        f=fm.getFunctionContaining(ins.getAddress())
        if f:
            for p in reversed(prev[-6:]):
                done=False
                for k in range(p.getNumOperands()):
                    for o in p.getOpObjects(k):
                        try:
                            v=o.getValue()&0xffffffff
                            if 1<=v<=0x40: func_mods[f.getEntryPoint().getOffset()][v]+=1; done=True;break
                        except:pass
                    if done:break
                if done:break
    prev.append(ins)
def modof(off):
    c=func_mods.get(off); return c.most_common(1)[0][0] if c else None
# MLME modules: 0x16 (build), 0x27 (mgmt tx). List funcs whose dominant module in these
MLME_MODS={0x16,0x27}
funcs=[(off,c.most_common(1)[0][0]) for off,c in func_mods.items() if c.most_common(1)[0][0] in MLME_MODS]
funcs.sort()
def nm(off):
    f=fm.getFunctionAt(sp.getAddress(off)); return f.getName() if f else 'FUN_%06x'%off
print('MLME functions (module 0x16=build / 0x27=mgmt-tx): %d'%len(funcs))
for off,m in funcs:
    f=fm.getFunctionAt(sp.getAddress(off))
    sz=f.getBody().getNumAddresses() if f else 0
    print('  0x%06x mod=0x%02x %5dB  %s'%(off,m,sz,nm(off)))
