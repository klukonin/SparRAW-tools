# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
import json,re
from collections import defaultdict
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
strs={int(k):v for k,v in json.load(open(getScriptArgs()[0])).items()}
UC_LO,UC_HI=0x920000,0x9380c4
FILE=re.compile(r'([A-Za-z0-9_]+\.(?:cpp|c|h))')
byfile=defaultdict(lambda:[0,0]); assigned={}
for f in fm.getFunctions(True):
    ep=f.getEntryPoint().getOffset()
    if not (UC_LO<=ep<UC_HI): continue
    files=[]; anystr=[]
    ins=listing.getInstructionAt(f.getEntryPoint()); end=f.getBody().getMaxAddress().getOffset()
    while ins is not None and ins.getAddress().getOffset()<=end:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v=o.getValue()
                except Exception: continue
                if isinstance(v,int) and (v>>24)==0x01:
                    s=strs.get(v&0xfffff)
                    if s:
                        anystr.append(s)
                        m=FILE.search(s)
                        if m: files.append(m.group(1))
        ins=ins.getNext()
    sz=f.getBody().getNumAddresses()
    if files:
        fn=max(set(files),key=files.count)
        byfile[fn][0]+=1; byfile[fn][1]+=sz; assigned[ep]=fn
print('ucode-функций привязано к файлу: %d'%len(assigned))
print('\nфайлы микрокода (функций / байт):')
for fn,(c,b) in sorted(byfile.items(),key=lambda kv:-kv[1][1]):
    print('  %-28s %3d ф. %6d Б'%(fn,c,b))
