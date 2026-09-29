# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Карта сборщиков информационных элементов: функции, чьи лог-строки говорят
# о добавлении IE в кадр.
import re
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mem=currentProgram.getMemory()
listing=currentProgram.getListing(); ref=currentProgram.getReferenceManager()
def rd(off,n=160):
    o=bytearray()
    for i in range(n):
        try: v=mem.getByte(sp.getAddress(off+i))&0xff
        except Exception: return None
        if v==0: break
        o.append(v)
    s=o.decode('latin1')
    return s if s and all(32<=ord(c)<127 for c in s) else None
KEY=re.compile(r'\b(Pushed|push|IE|ie_|element|Element)\b')
rows=[]
for f in fm.getFunctions(True):
    ep=f.getEntryPoint(); off=ep.getOffset()
    if off>=0x920000: continue
    ins=listing.getInstructionAt(ep); end=f.getBody().getMaxAddress().getOffset()
    hits=[]
    while ins is not None and ins.getAddress().getOffset()<=end:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v=o.getValue()
                except Exception: continue
                if isinstance(v,int) and 0x01000000<=v<0x0101b354:
                    s=rd(v)
                    if s and KEY.search(s): hits.append(s)
        ins=ins.getNext()
    if hits:
        us=set()
        for r in ref.getReferencesTo(ep):
            cf=fm.getFunctionContaining(r.getFromAddress())
            if cf: us.add(cf.getName())
        rows.append((off,f.getName(),f.getBody().getNumAddresses(),hits[0],sorted(us)[:3]))
rows.sort()
print('СБОРЩИКОВ %d'%len(rows))
for off,n,sz,s,us in rows:
    print('IE 0x%06x %-30s %4dБ | %-52s | %s'%(off,n,sz,s[:52],','.join(u.replace('FUN_ram_','') for u in us)[:44]))
