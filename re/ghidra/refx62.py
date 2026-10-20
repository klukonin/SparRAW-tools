# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import re
from collections import defaultdict
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
listing=currentProgram.getListing(); mem=currentProgram.getMemory()
PAT=re.compile(r'\br(?:3[2-9]|4[0-9]|5[0-9]|6[0-3])\b|\bmlo\b|\bmhi\b|mulu64|_LP_|\bnorm|\bswap|\bffs|\bfls|\babs|\bdiv|\bmpy|\bsr\b|\blr\b|\bex\b|\brtie\b|\bsleep\b|\btrap|\bbrk|\bseti|\bclri')
seen=defaultdict(list)
for lo,hi in ((0x8c0000,0x900000),(0x920000,0x940000)):
    ins=listing.getInstructionAt(sp.getAddress(lo)) or listing.getInstructionAfter(sp.getAddress(lo))
    while ins is not None and ins.getAddress().getOffset()<hi:
        t=ins.toString()
        if PAT.search(t):
            off=ins.getAddress().getOffset(); L=ins.getLength()
            try: b=bytes(bytearray((mem.getByte(sp.getAddress(off+i))&0xff) for i in range(L)))
            except Exception: ins=ins.getNext(); continue
            mn=ins.getMnemonicString(); ops=t[len(mn):].strip()
            shape=''.join('#' if c.isdigit() else ('r' if c.isalpha() else c) for c in ops)[:20]
            k='%s|%s'%(mn,shape)
            if not seen[k]: seen[k].append((off,b.hex(),t))
        ins=ins.getNext()
print('ЭКЗОТИКА ФОРМ %d'%len(seen))
for k in sorted(seen):
    off,hx,t=seen[k][0]; print('REF 0x%08x %-18s 1   %s'%(off,hx,t))
