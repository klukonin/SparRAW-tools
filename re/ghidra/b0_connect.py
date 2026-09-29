# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Phase B0: does Sparrow/Mikrotik 6.2 execute an ADHOC branch in the connect path?
import os, jpype
from ghidra.program.model.symbol import SourceType, RefType
from ghidra.program.model.data import TerminatedStringDataType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand

sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
mem=currentProgram.getMemory(); listing=currentProgram.getListing()
mon=ConsoleTaskMonitor()
args=getScriptArgs()
strings_bin=args[0]

STR_BASE=0x01000000
# --- map strings record @ 0x01000000 if absent ---
a0=sp.getAddress(STR_BASE)
if mem.getBlock(a0) is None:
    data=open(strings_bin,'rb').read()
    buf=jpype.JArray(jpype.JByte)(len(data))
    for i,b in enumerate(data): buf[i]=(b-256) if b>=128 else b
    blk=mem.createInitializedBlock('fw_strings',a0,len(data),0,mon,False)
    mem.setBytes(a0,buf); blk.setRead(True); blk.setWrite(False); blk.setExecute(False)
    print('mapped fw_strings %d B @0x01000000'%len(data))
else:
    print('fw_strings already present')

TARGETS={
 0x0100cc78:'str_NT_ADHOC', 0x0100ccdc:'str_NT_ADHOC_CREATOR',
 0x0100cc9c:'str_NT_P2P',   0x0100ccc0:'str_NT_INFRA_STA',
 0x0100cd08:'str_NT_INFRA_AP', 0x0100cd24:'str_NT_ILLEGAL',
 0x0100c3a4:'str_bss_set_mode', 0x010065e4:'str_network_type',
 0x0100cd6c:'str_PCP_handle_ch', 0x0100cdb4:'str_PBSS_PCP_start',
}
# label the strings
for off,nm in TARGETS.items():
    try: createLabel(sp.getAddress(off),nm,True,SourceType.USER_DEFINED)
    except: pass

def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f: return f.getName()
    ss=st.getSymbols(sp.getAddress(off)); return ss[0].getName() if ss else 'FUN_%06x'%off

# --- scan instructions for scalar operands == target string addr ---
refmap={t:set() for t in TARGETS}
it=listing.getInstructions(True)
cnt=0
while it.hasNext():
    ins=it.next(); cnt+=1
    for oi in range(ins.getNumOperands()):
        sc=ins.getScalar(oi)
        if sc is None: continue
        v=sc.getUnsignedValue()
        if v in refmap:
            f=fm.getFunctionContaining(ins.getAddress())
            fo=f.getEntryPoint().getOffset() if f else ins.getAddress().getOffset()
            refmap[v].add((fo, fname(fo), ins.getAddress().getOffset()))
            # add a data reference so the decompiler inlines the string
            try:
                currentProgram.getReferenceManager().addMemoryReference(
                    ins.getAddress(), sp.getAddress(v), RefType.DATA,
                    SourceType.USER_DEFINED, oi)
            except: pass
print('scanned %d instructions'%cnt)
print('\n===== who references each networkType string =====')
for t in sorted(TARGETS):
    rows=sorted(refmap[t])
    print('\n%-24s 0x%08x  (%d sites)'%(TARGETS[t],t,len(rows)))
    for fo,fn,site in rows:
        print('    %-40s @0x%06x  (func 0x%06x)'%(fn,site,fo))

# --- decompile the connect path ---
dec=DecompInterface(); dec.openProgram(currentProgram)
PATH=[('bss_set_mode',0x8c4eec),('l2_mgr::connect',0x8f1e18),
      ('validate_connect',0x8fb348),('l2_mgr::pcp_start',0x8f706c),
      ('bss_join_verify',0x8c4e80),('bss_set_active',0x8c4ec8),
      ('scan_mngr::connect',0x8f1f2c)]
# also whatever function(s) reference the ADHOC strings
for t in (0x0100cc78,0x0100ccdc,0x0100cd24):
    for fo,fn,site in sorted(refmap[t]):
        if (fn,fo) not in [(p[0],p[1]) for p in PATH]:
            PATH.append((fn,fo))

seen=set()
for tag,off in PATH:
    if off in seen: continue
    seen.add(off)
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: print('\n### %s @0x%06x NOT FOUND'%(tag,off)); continue
    print('\n\n########## %s @0x%06x (%d B) ##########'%(tag,f.getEntryPoint().getOffset(),f.getBody().getNumAddresses()))
    r=dec.decompileFunction(f,60,mon)
    if r and r.decompileCompleted():
        print(r.getDecompiledFunction().getC())
    else:
        print('  <decompile failed>')
