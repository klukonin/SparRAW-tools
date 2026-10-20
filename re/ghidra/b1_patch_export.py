# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import jpype
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory()
args=getScriptArgs()
orig=open(args[0],'rb').read(); base=int(args[1],16); out=args[2]
edit_addr=int(args[3],16); edit_bytes=bytes.fromhex(args[4])
# apply the edit in memory (not saved in -readOnly)
a0=sp.getAddress(edit_addr); a1=sp.getAddress(edit_addr+len(edit_bytes)-1)
clearListing(a0,a1)
eb=jpype.JArray(jpype.JByte)(len(edit_bytes))
for i,x in enumerate(edit_bytes): eb[i]=(x-256) if x>=128 else x
mem.setBytes(sp.getAddress(edit_addr),eb)
print('edited 0x%08x <- %s'%(edit_addr,edit_bytes.hex()))
# diff whole segment vs original blob
buf=jpype.JArray(jpype.JByte)(len(orig))
got=mem.getBytes(sp.getAddress(base),buf)
cur=bytes((buf[i]&0xff) for i in range(got))
runs=[]; i=0; n=min(len(orig),len(cur))
while i<n:
    if cur[i]!=(orig[i]&0xff):
        j=i
        while j<n and cur[j]!=(orig[j]&0xff): j+=1
        runs.append((base+i,cur[i:j])); i=j
    else: i+=1
open(out,'w').write(''.join('0x%08x: %s\n'%(a,d.hex()) for a,d in runs))
print('changed runs: %d, bytes: %d -> %s'%(len(runs),sum(len(d) for _,d in runs),out))
