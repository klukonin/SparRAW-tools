# @runtime PyGhidra
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
out=getScriptArgs()[0]; os.makedirs(out,exist_ok=True)
prog=currentProgram; fm=prog.getFunctionManager(); listing=prog.getListing(); mon=ConsoleTaskMonitor()
with open(os.path.join(out,'funcs.txt'),'w') as f:
    for fn in fm.getFunctions(True):
        f.write('%s %d %s\n'%(fn.getEntryPoint(),fn.getBody().getNumAddresses(),fn.getName()))
with open(os.path.join(out,'listing.dis'),'w') as f:
    for ins in listing.getInstructions(True):
        fn=fm.getFunctionContaining(ins.getAddress())
        f.write('%s\t%s\t%s\n'%(ins.getAddress(),ins,fn.getName() if fn else ''))
dec=DecompInterface(); dec.openProgram(prog)
with open(os.path.join(out,'decomp.c'),'w') as f:
    for fn in fm.getFunctions(True):
        r=dec.decompileFunction(fn,60,mon)
        f.write('\n/* ===== %s @ %s ===== */\n'%(fn.getName(),fn.getEntryPoint()))
        if r and r.decompileCompleted(): f.write(r.getDecompiledFunction().getC())
        else: f.write('/* decompile failed */\n')
print('EXPORT DONE', out)
