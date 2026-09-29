# SPDX-License-Identifier: AGPL-3.0-or-later
# Листинг диапазона: dis_range.py <start hex> <end hex>
a0=int(getScriptArgs()[0],16); a1=int(getScriptArgs()[1],16)
af=currentProgram.getAddressFactory().getDefaultAddressSpace()
lst=currentProgram.getListing()
a=af.getAddress(a0)
while a.getOffset()<a1:
    i=lst.getInstructionAt(a)
    if i is None:
        d=lst.getDataAt(a)
        print("%08x  %s" % (a.getOffset(), ("DATA "+str(d)) if d else "??"))
        a=a.add(2); continue
    print("%08x  %s" % (a.getOffset(), i))
    a=a.add(i.getLength())
