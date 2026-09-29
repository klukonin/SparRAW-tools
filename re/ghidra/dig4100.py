# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import jpype, json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
mem=currentProgram.getMemory(); mon=ConsoleTaskMonitor()
dec=DecompInterface(); dec.openProgram(currentProgram)
args=getScriptArgs()
# map strings @0x01000000
a0=sp.getAddress(0x01000000)
if mem.getBlock(a0) is None:
    data=open(args[0],'rb').read()
    buf=jpype.JArray(jpype.JByte)(len(data))
    for i,b in enumerate(data): buf[i]=(b-256) if b>=128 else b
    blk=mem.createInitializedBlock('fw_strings',a0,len(data),0,mon,False); mem.setBytes(a0,buf); blk.setRead(True)
    print("mapped strings %d B"%len(data))
TG=json.load(open(args[1]))  # {"0xADDR":desc}
TG={int(k,16):v for k,v in TG.items()}
def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off)); return f.getName() if f else 'FUN_%06x'%off
idx={t:set() for t in TG}
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    for oi in range(ins.getNumOperands()):
        sc=ins.getScalar(oi)
        if sc is not None and sc.getUnsignedValue() in idx:
            f=fm.getFunctionContaining(ins.getAddress())
            if f: idx[sc.getUnsignedValue()].add(f.getEntryPoint().getOffset())
print("\n===== CODE-BACKED check (4.1.0.1000) =====")
funcs=set()
for t in sorted(TG):
    fns=sorted(idx[t])
    mark="CODE-BACKED" if fns else "pool-only"
    print("[%s] 0x%08x %-46s : %s"%(mark,t,TG[t][:46],', '.join('%s@%06x'%(fname(f),f) for f in fns)))
    funcs|=set(fns)
print("\n===== decompile distributed-beacon functions =====")
for off in sorted(funcs):
    f=fm.getFunctionContaining(sp.getAddress(off))
    if not f: continue
    print("\n\n########## %s @0x%06x (%d B) ##########"%(fname(off),off,f.getBody().getNumAddresses()))
    r=dec.decompileFunction(f,50,mon)
    if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
