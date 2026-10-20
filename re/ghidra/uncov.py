# SPDX-License-Identifier: AGPL-3.0-or-later
# Find dispatcher handlers for security/datapath/PS commands and name workers.
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
listing=currentProgram.getListing(); mem=currentProgram.getMemory()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
TAIL=0x8dec72
def nm(off):
    a=sp.getAddress(off) if isinstance(off,int) else off
    f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==(off if isinstance(off,int) else a.getOffset()): return f.getName()
    ss=st.getSymbols(a); return ss[0].getName() if ss else 'FUN_%06x'%(off if isinstance(off,int) else a.getOffset())
def scalars(ins):
    out=[]
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try: out.append(o.getValue()&0xffffffff)
            except: pass
    return out
# target ids -> name
TARGET={0x16:'add_cipher_key',0x17:'del_cipher_key',0x821:'vring_cfg',0x822:'bcast_vring_cfg',
        0x823:'ring_ba_en',0x824:'ring_ba_dis',0x825:'addba_resp',0x826:'delba',
        0x91c:'ps_dev_profile',0x913:'power_mgmt_cfg',0xf04f:'pmc'}
# bound dispatcher
lo=hi=None
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next(); fl=ins.getFlows()
    if fl and any(f.getOffset()==TAIL for f in fl):
        o=ins.getAddress().getOffset(); lo=o if lo is None else min(lo,o); hi=o if hi is None else max(hi,o)
def body_calls(addr,budget=24):
    outs=[]; ins=listing.getInstructionAt(addr)
    for _ in range(budget):
        if ins is None: break
        ft=ins.getFlowType(); fl=ins.getFlows()
        if fl and any(f.getOffset()==TAIL for f in fl): break
        if ft.isCall() and fl and mem.getBlock(fl[0]) is not None: outs.append(fl[0].getOffset())
        ins=ins.getNext()
    return outs
import collections
cases={}
ins=listing.getInstructionAt(sp.getAddress(lo-0x80))
while ins is not None and ins.getAddress().getOffset()<=hi:
    for v in scalars(ins):
        if v in TARGET:
            cur=ins.getNext()
            for _ in range(4):
                if cur is None: break
                ft=cur.getFlowType(); fl=cur.getFlows()
                if ft.isJump() and ft.isConditional() and fl:
                    cases.setdefault(v,body_calls(fl[0])); break
                cur=cur.getNext()
            break
    ins=ins.getNext()
freq=collections.Counter(t for ts in cases.values() for t in ts)
HELP={t for t,c in freq.items() if c>=3}
for v,ts in sorted(cases.items()):
    cand=[t for t in ts if t not in HELP]
    cand.sort(key=lambda t:(freq[t],t))
    h=cand[0] if cand else (ts[0] if ts else None)
    if h:
        f=fm.getFunctionContaining(sp.getAddress(h))
        if f and f.getEntryPoint().getOffset()==h and f.getName().startswith('FUN_'):
            f.setName('wmi_h_%s'%TARGET[v],SourceType.USER_DEFINED)
        print('0x%04x %-18s -> 0x%06x %s'%(v,TARGET[v],h,nm(h)))
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_','conn_','get_link','mgmt_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
