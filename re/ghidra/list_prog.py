# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
print('PROGRAM %s | %d функций | блоки: %s' % (
    currentProgram.getName(),
    currentProgram.getFunctionManager().getFunctionCount(),
    ', '.join('%s@0x%x' % (b.getName(), b.getStart().getOffset())
              for b in currentProgram.getMemory().getBlocks())))
