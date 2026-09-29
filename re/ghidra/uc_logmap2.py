# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# ucode string ref convention: instruction constant = 0x01000000 | ucode_string_offset
import json
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); listing=currentProgram.getListing()
args=getScriptArgs()
STR={int(k):v for k,v in json.load(open(args[0])).items()}
BASE=0x01000000
enc={BASE|off:off for off in STR}
def fname(o):
    f=fm.getFunctionContaining(sp.getAddress(o)); return f.getName() if f else None
hits={}; tot=0
it=listing.getInstructions(True)
while it.hasNext():
    ins=it.next(); a=ins.getAddress().getOffset()
    if not (0x920000 <= a < 0x940000): continue
    for oi in range(ins.getNumOperands()):
        sc=ins.getScalar(oi)
        if sc is None: continue
        v=sc.getUnsignedValue()
        if v in enc:
            off=enc[v]; f=fm.getFunctionContaining(ins.getAddress())
            fo=f.getEntryPoint().getOffset() if f else None
            hits.setdefault(off,[]).append((a,fo)); tot+=1
print("ucode log call-sites: %d ; distinct strings: %d (of %d in table)"%(tot,len(hits),len(STR)))
funcs={}
for off,lst in hits.items():
    for a,fo in lst:
        if fo: funcs.setdefault(fo,set()).add(off)
import re
kw=re.compile(r'beacon|bcon|bti|atim|AW|TBTT|nav|backoff|random|defer|discovery|peer|NNL',re.I)
print("\n===== BEACON/NNL-related ucode log sites =====")
for off in sorted(hits):
    if kw.search(STR[off]):
        print("\n[0x%05x] %s"%(off,STR[off][:78]))
        for a,fo in hits[off][:5]:
            print("    0x%06x  %s"%(a,('%s@%06x'%(fname(fo),fo)) if fo else '-'))
print("\n===== top ucode functions by distinct log strings =====")
for fo,offs in sorted(funcs.items(), key=lambda x:-len(x[1]))[:20]:
    names=' ; '.join(sorted(STR[o][:34] for o in offs))[:160]
    print("  %s @0x%06x : %2d | %s"%(fname(fo),fo,len(offs),names))
