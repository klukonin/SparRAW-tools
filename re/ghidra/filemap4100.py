# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import jpype, json, collections
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
mem=currentProgram.getMemory(); mon=ConsoleTaskMonitor()
args=getScriptArgs()
a0=sp.getAddress(0x01000000)
if mem.getBlock(a0) is None:
    d=open(args[0],'rb').read()
    buf=jpype.JArray(jpype.JByte)(len(d))
    for i,b in enumerate(d): buf[i]=(b-256) if b>=128 else b
    blk=mem.createInitializedBlock('fw_strings',a0,len(d),0,mon,False); mem.setBytes(a0,buf); blk.setRead(True)
FILES={int(k,16):v for k,v in json.load(open(args[1])).items()}
def fname(off):
    f=fm.getFunctionContaining(sp.getAddress(off)); return f.getName() if f else 'FUN_%06x'%off
fn2file=collections.defaultdict(set); file2fn=collections.defaultdict(set)
it=listing.getInstructions(True); n=0
while it.hasNext():
    ins=it.next(); n+=1
    for oi in range(ins.getNumOperands()):
        sc=ins.getScalar(oi)
        if sc is not None:
            v=sc.getUnsignedValue()
            if v in FILES:
                f=fm.getFunctionContaining(ins.getAddress())
                if f:
                    off=f.getEntryPoint().getOffset()
                    fn2file[off].add(FILES[v]); file2fn[FILES[v]].add(off)
print("scanned %d insns; functions with file attribution: %d; files hit: %d"%(n,len(fn2file),len(file2fn)))
out=[]
for fl in sorted(file2fn, key=lambda x:-len(file2fn[x])):
    out.append((fl,sorted(file2fn[fl])))
print("\n=== functions per source file (top 30) ===")
for fl,fns in out[:30]:
    print("%-30s %3d : %s"%(fl,len(fns),' '.join('%06x'%f for f in fns[:12])))
# dump full map
with open(args[2],'w') as fh:
    for fl,fns in sorted(out):
        for f in fns: fh.write("0x%06x  %s\n"%(f,fl))
print("\nwrote map ->",args[2])
