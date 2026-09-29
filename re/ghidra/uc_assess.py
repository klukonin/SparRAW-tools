# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager()
listing=currentProgram.getListing()
mem=currentProgram.getMemory()
# uc_code block 0x920000..0x93c608 (116232 B)
lo,hi=0x920000,0x920000+116232
fns=[f for f in fm.getFunctions(True) if lo<=f.getEntryPoint().getOffset()<hi]
# count instructions in uc_code
it=listing.getInstructions(sp.getAddress(lo),True); ni=0
while it.hasNext():
    a=it.next().getAddress().getOffset()
    if a>=hi: break
    ni+=1
print('uc_code 0x%06x..0x%06x: %d functions, %d instructions'%(lo,hi,len(fns),ni))
# first bytes / entry
d=bytearray(16); mem.getBytes(sp.getAddress(lo),d)
print('first bytes: '+' '.join('%02x'%(b&0xff) for b in d))
# uc_data block
print('uc_data block:', mem.getBlock(sp.getAddress(0x940000)))
