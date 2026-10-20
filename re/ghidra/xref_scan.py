# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Прямой поиск инструкций, чья цель перехода = заданный адрес (минуя Ghidra-ссылки).
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()
targets=set(int(x,16) for x in getScriptArgs()[0].split(','))
hits={t:[] for t in targets}
for lo,hi in ((0x8c0000,0x8f3b58),(0x920000,0x9380c4)):
    ins=listing.getInstructionAt(sp.getAddress(lo)) or listing.getInstructionAfter(sp.getAddress(lo))
    while ins is not None and ins.getAddress().getOffset()<hi:
        for fl in (ins.getFlows() or []):
            t=fl.getOffset()
            if t in targets:
                f=fm.getFunctionContaining(ins.getAddress())
                hits[t].append((ins.getAddress().getOffset(), f.getName() if f else '(вне функций)', ins.toString()))
        ins=ins.getNext()
for t in sorted(targets):
    print('\n=== переходы на 0x%06x: %d ==='%(t,len(hits[t])))
    for a,fn,txt in hits[t][:10]:
        print('   0x%06x  %-34s %s'%(a,fn,txt))

# соседи ps_assoc_mgr: что рядом и кто на них ссылается
print('\n=== окружение 0x8c34f4 (класс ps_assoc_mgr?) ===')
ref=currentProgram.getReferenceManager()
for f in fm.getFunctions(True):
    o=f.getEntryPoint().getOffset()
    if not (0x8c3300<=o<0x8c3800): continue
    n=len(list(ref.getReferencesTo(f.getEntryPoint())))
    print('   0x%06x %-40s %4dБ  ссылок: %d'%(o,f.getName(),f.getBody().getNumAddresses(),n))
