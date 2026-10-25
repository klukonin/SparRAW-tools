# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
import collections
path=getScriptArgs()[0]; fm=currentProgram.getFunctionManager(); af=currentProgram.getAddressFactory().getDefaultAddressSpace()
rows=[l.rstrip('\n').split('\t') for l in open(path) if not l.startswith('#')]
cnt=collections.Counter(r[2] for r in rows if len(r)>3)
used=collections.Counter(); ap=0
for r in rows:
    if len(r)<4: continue
    fname,k,name,ev=r
    f=None
    for fn in [fm.getFunctions(True)]: pass
    addr=fname.split('_')[-1]
    try: f=fm.getFunctionAt(af.getAddress(int(addr,16)))
    except Exception: f=None
    if f is None or not f.getName().startswith('FUN_'): continue
    base='fwlog_'+name if cnt[name]<=2 else 'file_'+name
    used[base]+=1
    nm=base if used[base]==1 else '%s_%d'%(base,used[base])
    f.setName(nm,SourceType.USER_DEFINED)
    f.setComment(('из лог-строки: '+ev.strip('| ').strip())[:400]); ap+=1
print('NAMES APPLIED',ap)
