# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); mon=ConsoleTaskMonitor()
dec=DecompInterface(); dec.openProgram(currentProgram)
# candidate IE parsers: functions in fw_code with a loop; check decompiled text for
# the element-walk idiom: "+ 2" advance and "[.. + 1]" length read in a loop.
hits=[]
fi=fm.getFunctions(sp.getAddress(0x8c0000),True)
import re
cnt=0
for f in fi:
    ep=f.getEntryPoint().getOffset()
    if ep>=0x900000: break
    sz=f.getBody().getNumAddresses()
    if not (60<=sz<=800): continue
    # quick: only decompile funcs whose name is FUN_ and in the mgmt/ie clusters
    if not (0x8ce000<=ep<0x8d3000 or 0x8d5000<=ep<0x8d6000): continue
    r=dec.decompileFunction(f,15,mon)
    if not (r and r.decompileCompleted()): continue
    c=r.getDecompiledFunction().getC()
    # element walk idiom
    if re.search(r'\+ 2;',c) and re.search(r'\[.*\+ 1\]|\(.*\+ 1\)',c) and ('do {' in c or 'while' in c or 'for ' in c):
        hits.append((ep,sz,f.getName()))
    cnt+=1
    if cnt>200: break
print('IE-parser-idiom candidates (loop + len-read + advance-by-2):')
for ep,sz,n in hits[:15]: print('  0x%06x %4dB %s'%(ep,sz,n))
