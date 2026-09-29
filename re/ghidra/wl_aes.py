# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram; fm=prog.getFunctionManager(); ref=prog.getReferenceManager(); mem=prog.getMemory(); mon=ConsoleTaskMonitor()
sp=prog.getAddressFactory().getDefaultAddressSpace()
dec=DecompInterface(); dec.openProgram(prog)
def find_str(s):
    return mem.findBytes(prog.getMinAddress(),s.encode()+b'\x00',None,True,mon)
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else 'sub_%x'%a.getOffset()
# AES string xrefs -> the functions AES_set_decrypt_key etc. (or assert sites)
for aname in ('AES_set_decrypt_key','AES_set_encrypt_key','AES_decrypt','AES_encrypt'):
    a=find_str(aname)
    if a is None: print('%s: string not found'%aname); continue
    users=set()
    for r in ref.getReferencesTo(a):
        users.add(nm(r.getFromAddress()))
    print('%-22s @%s  ref-by: %s'%(aname,a,users))
# find funcs that call AES setup: look at FUN_000a540c full decompile for AES/key/tables
f=fm.getFunctionAt(sp.getAddress(0xa540c))
r=dec.decompileFunction(f,90,mon)
if r and r.decompileCompleted():
    c=r.getDecompiledFunction().getC()
    import re
    for l in c.split('\n'):
        s=l.strip()
        if re.search(r'FUN_000[0-9a-f]+\(.*0x[0-9a-f]{5,}',s) or 'DAT_' in s and ('key' in s.lower() or True) and ('FUN_' in s):
            pass
    # print calls with a large-const (potential key ptr) argument
    for l in c.split('\n'):
        s=l.strip()
        if 'FUN_' in s and 'DAT_000' in s: print('  '+s[:110])
