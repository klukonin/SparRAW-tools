# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram
fm=prog.getFunctionManager(); ref=prog.getReferenceManager(); mem=prog.getMemory()
dec=DecompInterface(); dec.openProgram(prog); mon=ConsoleTaskMonitor()
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else '(top)'
def find_str(s):
    b=s.encode()+b'\x00'
    a=mem.findBytes(prog.getMinAddress(),b,None,True,mon)
    return a
targets=['wil6210.fw','bad firmware file format','wil6210-','/pckg/wireless/lib/firmware/']
funcs=set()
for t in targets:
    a=find_str(t)
    if a is None: print('str NOT found:',t); continue
    users=[]
    for r in ref.getReferencesTo(a):
        f=fm.getFunctionContaining(r.getFromAddress())
        if f: funcs.add(f.getEntryPoint().getOffset()); users.append(f.getName())
    print('str %-32s @%s  used by: %s'%(repr(t),a,set(users)))
# AES functions by symbol
for aname in ('AES_set_decrypt_key','AES_decrypt','AES_set_encrypt_key','AES_cbc_encrypt','AES_ctr128_encrypt'):
    a=find_str(aname)
    # symbol may be a function name too
print('\n=== functions referencing fw strings + their callees ===')
sp=prog.getAddressFactory().getDefaultAddressSpace()
for off in sorted(funcs):
    f=fm.getFunctionAt(sp.getAddress(off))
    callees=sorted(set(nm(c.getEntryPoint()) for c in f.getCalledFunctions(mon)))
    interesting=[c for c in callees if any(k in c.lower() for k in ('aes','crypt','xor','key','sha','md5','read','open','fw','firm'))]
    print('  0x%06x %-18s %dB  callees(crypto/io): %s'%(off,f.getName(),f.getBody().getNumAddresses(),interesting[:8]))
