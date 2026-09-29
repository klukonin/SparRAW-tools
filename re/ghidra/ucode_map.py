# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Карта подсистем микрокода: для каждой функции uc_code собрать её лог-строки
# (конвенция 0x01000000|offset, маска биты[19:0]) и сгруппировать по «теме».
import json,re
from collections import defaultdict
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
strs={int(k):v for k,v in json.load(open(getScriptArgs()[0])).items()}
UC_LO,UC_HI=0x920000,0x9380c4
rows=[]
for f in fm.getFunctions(True):
    ep=f.getEntryPoint().getOffset()
    if not (UC_LO<=ep<UC_HI): continue
    hits=[]
    ins=listing.getInstructionAt(f.getEntryPoint()); end=f.getBody().getMaxAddress().getOffset()
    while ins is not None and ins.getAddress().getOffset()<=end:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v=o.getValue()
                except Exception: continue
                if isinstance(v,int) and (v>>24)==0x01:
                    s=strs.get(v&0xfffff)
                    if s and len(s)>3: hits.append(s)
        ins=ins.getNext()
    if hits: rows.append((ep,f.getBody().getNumAddresses(),hits))
print('функций ucode со строками: %d'%len(rows))
# темы по ключевым словам
TH=[('BF/AOA',r'\bbf\b|beamform|aoa|sls|brp|txss|rxss|sector|abft'),
    ('RX/BA',r'\brx\b|mpdu|ampdu|reorder|\bba\b|bar|block ?ack|qos'),
    ('beacon/AW',r'beacon|bcon|\baw\b|atim|tbtt|\bbti\b|discovery|nav'),
    ('TX/sched',r'\btx\b|schedul|slot|allocation|dti|internal_tx|initiator|eligibility'),
    ('RF/calib',r'\brf\b|calib|gain|rfc|temperat|mrfc|hwd_'),
    ('power',r'sleep|power|wakeup|doze|awake|psm|l1'),
    ('crash/dbg',r'crash|assert|fatal|sysassert|dump|error')]
cat=defaultdict(lambda:[0,0])
for ep,sz,hits in rows:
    blob=' '.join(hits).lower()
    tag='прочее'
    for name,rx in TH:
        if re.search(rx,blob): tag=name; break
    cat[tag][0]+=1; cat[tag][1]+=sz
print('\nтемы (функций / байт):')
for t,(c,b) in sorted(cat.items(),key=lambda kv:-kv[1][1]):
    print('  %-12s %3d ф. %6d Б'%(t,c,b))
