# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Контекст проверок r42: три инструкции перед каждым tst/and с r42,
# чтобы увидеть, какая маска кладётся в регистр.
lst = currentProgram.getListing()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
it = lst.getInstructions(af.getAddress(0x920000), True)
buf = []
while it.hasNext():
    i = it.next()
    a = i.getAddress().getOffset()
    if a >= 0x9380c4:
        break
    s = str(i)
    buf.append((a, s))
    if len(buf) > 5:
        buf.pop(0)
    if ('r42' in s) and (s.startswith('tst') or s.startswith('and') or s.startswith('bmsk')):
        print("CTX ---- %06x %s" % (a, s))
        for aa, ss in buf[:-1]:
            print("CTX      %06x %s" % (aa, ss))
