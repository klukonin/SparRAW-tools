# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import jpype
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType, RefType
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
mem=currentProgram.getMemory(); listing=currentProgram.getListing()
rm=currentProgram.getReferenceManager()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
args=getScriptArgs()
# ensure strings block
a0=sp.getAddress(0x01000000)
if mem.getBlock(a0) is None and len(args)>0:
    data=open(args[0],'rb').read()
    buf=jpype.JArray(jpype.JByte)(len(data))
    for i,b in enumerate(data): buf[i]=(b-256) if b>=128 else b
    blk=mem.createInitializedBlock('fw_strings',a0,len(data),0,mon,False)
    mem.setBytes(a0,buf); blk.setRead(True)
def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f: return f.getName()
    return 'FUN_%06x'%off
# string addr -> label
STR={0x0100b448:'wmi_pcp_start_cmd_handler',0x01016d24:'pcp_start()',
 0x01013da0:'Build_DMG_Beacon',0x01009244:'update_pcp_ap_TRUE',
 0x01004b04:'Send_CMD_BCON_MGT',0x0100498c:'lmac_if_trigger_bf',
 0x01010d4c:'Info_flow_Not_PCP_AP',0x0100c3dc:'bss_bi_ctrl_PCP_ready_set',
 0x01004aac:'bcn_tx_init_ss_params',0x0100c988:'assoc_ready_check_trig',
 0x0100ce08:'PCP_Start_failed_BSS_not_ready'}
# build reverse index by scanning scalars
idx={s:set() for s in STR}
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    for oi in range(ins.getNumOperands()):
        sc=ins.getScalar(oi)
        if sc is not None and sc.getUnsignedValue() in idx:
            f=fm.getFunctionContaining(ins.getAddress())
            if f: idx[sc.getUnsignedValue()].add(f.getEntryPoint().getOffset())
print('===== string -> referencing functions =====')
funcs_to_decomp=set()
for s in sorted(STR):
    fns=sorted(idx[s])
    print('%-30s 0x%08x : %s'%(STR[s],s,', '.join('%s@%06x'%(fname(f),f) for f in fns) or '(none)'))
    for f in fns: funcs_to_decomp.add(f)
# explicit adds
for x in (0x8f706c,0x8e0778):
    funcs_to_decomp.add(x)
print('\n===== decompile beacon/PCP layer =====')
for off in sorted(funcs_to_decomp):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: continue
    callees=sorted(set(fname(c.getEntryPoint().getOffset()) for c in f.getCalledFunctions(mon)))
    callees=[c for c in callees if 'log' not in c.lower()]
    print('\n\n########## %s @0x%06x (%d B) calls: %s'%(fname(off),off,f.getBody().getNumAddresses(),', '.join(callees[:16])))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
    else: print('  <decompile failed>')
