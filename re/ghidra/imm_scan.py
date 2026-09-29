# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Поиск инструкций, материализующих заданный адрес как НЕПОСРЕДСТВЕННОЕ значение
# (установка обработчика в объект: mov rX,<addr> ; st rX,[obj,off]).
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()
targets=set(int(x,16) for x in getScriptArgs()[0].split(','))
for lo,hi in ((0x8c0000,0x8f3b58),(0x920000,0x9380c4)):
    ins=listing.getInstructionAt(sp.getAddress(lo)) or listing.getInstructionAfter(sp.getAddress(lo))
    while ins is not None and ins.getAddress().getOffset()<hi:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v=o.getValue()
                except Exception: continue
                if isinstance(v,int) and v in targets:
                    f=fm.getFunctionContaining(ins.getAddress())
                    # покажем и следующую инструкцию — обычно там store в объект
                    nxt=ins.getNext()
                    print('IMM 0x%06x  в %-34s : %-30s ; next: %s'%(
                        ins.getAddress().getOffset(),
                        f.getName() if f else '(вне функций)',
                        ins.toString(), nxt.toString() if nxt else '-'))
        ins=ins.getNext()
print('ГОТОВО')
