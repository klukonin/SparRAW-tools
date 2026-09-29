# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import collections
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); ref=currentProgram.getReferenceManager()
mon=ConsoleTaskMonitor()
lo,hi=0x920000,0x93c608
ucf=[f for f in fm.getFunctions(True) if lo<=f.getEntryPoint().getOffset()<hi]
# biggest functions
bysize=sorted(ucf,key=lambda f:-f.getBody().getNumAddresses())[:12]
print('=== biggest uc_code functions (core handlers) ===')
for f in bysize:
    print('  0x%06x %5dB'%(f.getEntryPoint().getOffset(),f.getBody().getNumAddresses()))
# most-referenced (core helpers) within uc_code
indeg=collections.Counter()
for f in ucf:
    for r in ref.getReferencesTo(f.getEntryPoint()):
        if r.getReferenceType().isCall(): indeg[f.getEntryPoint().getOffset()]+=1
print('=== most-called uc_code functions (core primitives) ===')
for off,c in indeg.most_common(12):
    print('  0x%06x  called %d x  (%dB)'%(off,c,fm.getFunctionAt(sp.getAddress(off)).getBody().getNumAddresses()))
# does uc reference fw_code (cross-segment)? and RGF regions touched
print('=== uc_code RGF/shared-mem regions touched (top) ===')
rgf=collections.Counter()
listing=currentProgram.getListing()
it=listing.getInstructions(sp.getAddress(lo),True)
while it.hasNext():
    ins=it.next()
    if ins.getAddress().getOffset()>=hi: break
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try:
                v=o.getValue()&0xffffffff
                if 0x880000<=v<0x8a0000: rgf[v&0xffff00]+=1
                elif 0x940000<=v<0x942000: rgf[0x940000]+=1   # uc_data
            except: pass
for r,c in rgf.most_common(10): print('  0x%06x : %d'%(r,c))
