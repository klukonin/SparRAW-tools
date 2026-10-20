# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
prog=currentProgram; fm=prog.getFunctionManager(); ref=prog.getReferenceManager(); mon=ConsoleTaskMonitor()
st=prog.getSymbolTable(); sp=prog.getAddressFactory().getDefaultAddressSpace()
dec=DecompInterface(); dec.openProgram(prog)
def nm(a):
    f=fm.getFunctionContaining(a); return f.getName() if f else 'sub_%x'%a.getOffset()
# find AES symbols (functions) by name
for s in st.getAllSymbols(False):
    n=s.getName()
    if n.startswith('AES_') or n in ('AES_decrypt','AES_encrypt','AES_set_decrypt_key','AES_set_encrypt_key'):
        a=s.getAddress()
        callers=set()
        for r in ref.getReferencesTo(a):
            callers.add(nm(r.getFromAddress()))
        print('%-22s @%s  type=%s callers=%s'%(n,a,s.getSymbolType(),callers))
