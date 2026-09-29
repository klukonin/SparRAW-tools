# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Таблица переходников доступа к битовым полям.
# Каждый: mov r10,<сдвиг>; b.d <помощник>; mov r11,<ширина-1>
# Ядро 0x8e8868: маска = bmsk(-1, r11) шириной r11+1, сдвиг r10.
from collections import defaultdict
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
ref=currentProgram.getReferenceManager()

def imm(ins):
    for i in range(ins.getNumOperands()):
        for o in ins.getOpObjects(i):
            try: v=o.getValue()
            except Exception: continue
            if isinstance(v,int) and v<0x1000: return v
    return None

rows=[]
for f in fm.getFunctions(True):
    ep=f.getEntryPoint(); off=ep.getOffset()
    if off>=0x920000: continue
    n=f.getBody().getNumAddresses()
    if n>16: continue
    ins=listing.getInstructionAt(ep)
    seq=[]
    cur=ins
    for _ in range(3):
        if cur is None: break
        seq.append(cur); cur=cur.getNext()
    if len(seq)<3: continue
    t0,t1,t2=[x.toString().lstrip('_') for x in seq]  # _ = слот задержки
    if not (t0.startswith('mov') and 'r10' in t0 and t2.startswith('mov') and 'r11' in t2): continue
    if not t1.startswith(('b','j')): continue
    shift=imm(seq[0]); width=imm(seq[2])
    if shift is None or width is None: continue
    helper=None
    fl=seq[1].getFlows()
    if fl and len(fl)>0: helper=fl[0].getOffset()
    callers=set()
    for r in ref.getReferencesTo(ep):
        cf=fm.getFunctionContaining(r.getFromAddress())
        if cf: callers.add(cf.getName())
    rows.append((off,helper,shift,width+1,sorted(callers)))
rows.sort()
print('ПЕРЕХОДНИКОВ %d'%len(rows))
byh=defaultdict(int)
for _,h,_,_,_ in rows: byh[h]+=1
print('помощники: %s'%', '.join('%s x%d'%(('0x%06x'%h) if h else '?',c) for h,c in sorted(byh.items(), key=lambda kv:-kv[1])))
for off,h,s,w,c in rows:
    print('BF 0x%06x helper=0x%06x shift=%-2d width=%-2d users=%s'%(off,h or 0,s,w,','.join(c[:3]) or '-'))
