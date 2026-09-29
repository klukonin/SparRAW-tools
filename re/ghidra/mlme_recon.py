# SPDX-License-Identifier: AGPL-3.0-or-later
# Recon MLME: find the mgmt-frame subtype dispatcher and MLME WMI handlers.
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else '(top)'
# 1) MLME WMI handler (WMI_MLME_PUSH_CMDID=0x835 was in dispatcher); decompile it
for lbl in ('wmi_h_connect',):
    s=st.getGlobalSymbols(lbl)
    if s:
        f=fm.getFunctionAt(s[0].getAddress())
        # already known thin
# 2) Find a management-frame subtype dispatcher: a function comparing a value
#    against many of {0,1,2,3,0xa,0xb,0xc,0xd} (assoc/auth/deauth subtypes) OR
#    referencing 802.11 mgmt. Heuristic: functions with >=4 distinct compares to
#    small subtype-like constants near each other. Instead, scan for the frame
#    RX: functions logging with a plausible MLME module. First list module usage.
import collections
LOGS={0x8dc6c0,0x8dc748,0x8dc7a0,0x8dc8b4}
modcount=collections.Counter()
modfuncs=collections.defaultdict(set)
it=listing.getInstructions(True)
prev=[]
while it.hasNext():
    ins=it.next()
    fl=ins.getFlows()
    if ins.getFlowType().isCall() and fl and fl[0].getOffset() in LOGS:
        for p in reversed(prev[-6:]):
            done=False
            for k in range(p.getNumOperands()):
                for o in p.getOpObjects(k):
                    try:
                        v=o.getValue()&0xffffffff
                        if 1<=v<=0x40:
                            modcount[v]+=1
                            f=fm.getFunctionContaining(ins.getAddress())
                            if f: modfuncs[v].add(f.getName())
                            done=True;break
                    except:pass
                if done:break
            if done:break
    prev.append(ins)
print('log modules by frequency (module: count):')
for m,c in modcount.most_common(20):
    print('  0x%02x: %d'%(m,c))
