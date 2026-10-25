# @runtime PyGhidra
# Точки входа для образа Sparrow: таблица векторов ARC в начале кода (32 вектора по 8 байт).
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
base = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(getScriptArgs()[0], 16))
for i in range(32):
    a = base.add(8 * i)
    DisassembleCommand(a, None, True).applyTo(currentProgram, monitor)
CreateFunctionCmd(base).applyTo(currentProgram, monitor)
print('SP ENTRY', base)
