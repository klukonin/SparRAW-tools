# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import jpype
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
mem=currentProgram.getMemory(); mon=ConsoleTaskMonitor()
dec=DecompInterface(); dec.openProgram(currentProgram)
args=getScriptArgs()
a0=sp.getAddress(0x01000000)
if mem.getBlock(a0) is None:
    d=open(args[0],'rb').read()
    buf=jpype.JArray(jpype.JByte)(len(d))
    for i,b in enumerate(d): buf[i]=(b-256) if b>=128 else b
    blk=mem.createInitializedBlock('fw_strings',a0,len(d),0,mon,False); mem.setBytes(a0,buf); blk.setRead(True)
def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off)); return f.getName() if f else 'FUN_%06x'%off
# 1) who touches the NNL counter cluster 0x854de4..0x854e50
LO,HI=0x854de4,0x854e50
touch={}
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next()
    for oi in range(ins.getNumOperands()):
        sc=ins.getScalar(oi)
        if sc is not None:
            v=sc.getUnsignedValue()
            if LO<=v<=HI:
                f=fm.getFunctionContaining(ins.getAddress())
                if f:
                    o=f.getEntryPoint().getOffset()
                    touch.setdefault(o,set()).add(v)
print("=== functions touching NNL counter cluster 0x%06x-0x%06x ==="%(LO,HI))
for o in sorted(touch): print("  %-22s @0x%06x  addrs:%s"%(fname(o),o,[hex(x) for x in sorted(touch[o])][:10]))
# 2) decompile the key mesh files' functions
GRP={'bad_beacons_detector':[0x8c5a34,0x8d5f8c,0x8d70fc],
     'discovery':[0x8c7c80,0x8edbbc,0x8f01ac,0x8f12f8],
     'tx_bcon':[0x8c2190,0x8c22e4],
     'fw_scheduled_dti':[0x8db5b4,0x8e5708,0x8e7418]}
for g,offs in GRP.items():
    for off in offs:
        f=fm.getFunctionContaining(sp.getAddress(off))
        if not f: continue
        print("\n\n########## [%s] %s @0x%06x (%d B) ##########"%(g,fname(off),off,f.getBody().getNumAddresses()))
        r=dec.decompileFunction(f,50,mon)
        if r and r.decompileCompleted(): print(r.getDecompiledFunction().getC())
