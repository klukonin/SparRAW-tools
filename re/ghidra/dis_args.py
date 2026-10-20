# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Дизассемблер участка: dis_args.py <адрес> [сколько_инструкций]
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()
args = getScriptArgs()
start = int(args[0], 16)
n = int(args[1]) if len(args) > 1 else 40
ins = listing.getInstructionAt(af.getAddress(start))
if ins is None:
    ins = listing.getInstructionContaining(af.getAddress(start))
i = 0
while ins is not None and i < n:
    print('%s  %-42s %s' % (ins.getAddress(), ins.toString(),
                            ' ; ' + (listing.getComment(0, ins.getAddress()) or '')))
    ins = ins.getNext()
    i += 1
