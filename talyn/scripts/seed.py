# @runtime PyGhidra
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
path=getScriptArgs()[0]
af=currentProgram.getAddressFactory().getDefaultAddressSpace(); listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()
n=0; new=0
for line in open(path):
    line=line.strip()
    if not line: continue
    a=af.getAddress(int(line,16)); n+=1
    if listing.getInstructionAt(a) is None and listing.getDataAt(a) is None or (listing.getDataAt(a) is not None and not listing.getDataAt(a).isDefined()):
        if DisassembleCommand(a,None,True).applyTo(currentProgram,monitor): new+=1
mgr=AutoAnalysisManager.getAnalysisManager(currentProgram)
mgr.reAnalyzeAll(None); mgr.startAnalysis(monitor)
print('SEED', n, 'disassembled-new', new, 'functions', fm.getFunctionCount())
