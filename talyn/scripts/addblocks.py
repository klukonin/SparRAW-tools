# @runtime PyGhidra
import os
from ghidra.program.model.address import AddressSet
args=getScriptArgs(); d=args[0]; kind=args[1]
mem=currentProgram.getMemory(); af=currentProgram.getAddressFactory()
mp=[l.split() for l in open(os.path.join(d,'map.txt')) if l.strip()]
from java.io import ByteArrayInputStream
for ahb,lnk,reg in mp:
    ahb=int(ahb,16); lnk=int(lnk,16)
    want = (kind=='fw' and reg.startswith('fw')) or (kind=='uc' and reg.startswith('uc'))
    if not want or lnk==0: continue
    data=open(os.path.join(d,'%x.bin'%ahb),'rb').read()
    a=af.getDefaultAddressSpace().getAddress(lnk)
    blk=mem.createInitializedBlock('%s_%x'%(reg,lnk),a,ByteArrayInputStream(data),len(data),monitor,False)
    blk.setRead(True); blk.setWrite(True); blk.setExecute(reg.endswith('code'))
    print('block',reg,hex(lnk),len(data))
# peripheral window (RGF/PHY/MAC) for reference resolution
a=af.getDefaultAddressSpace().getAddress(0x880000)
b=mem.createUninitializedBlock('RGF',a,0x40000,False); b.setVolatile(True); b.setRead(True); b.setWrite(True)
