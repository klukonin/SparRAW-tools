# SPDX-License-Identifier: AGPL-3.0-or-later
# Build the whole wil6210/Talyn firmware image into ONE Ghidra program:
# a memory block per loadable segment, the FW and ucode data types applied,
# the reset vector marked, and auto-analysis over the ARC code.
#
# Import any one segment blob first (seg_00900000.bin at 0x900000); this
# script adds the rest.  Arg: the project-kit directory.
#
#   -noanalysis -preScript wil_build_project.py <kit-dir>
#
# @category wil6210
# @runtime PyGhidra
import json
import os

import jpype
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType

kit = getScriptArgs()[0]
seg = json.load(open(os.path.join(kit, 'segments.json')))
try:
    proj = json.load(open(os.path.join(kit, 'project.json')))
    ENTRY = int(proj.get('entry', 0x900000))
except Exception:
    ENTRY = min([s['addr'] for s in seg if s.get('exec')] or [0x900000])
mem = currentProgram.getMemory()
space = currentProgram.getAddressFactory().getDefaultAddressSpace()


def jbytes(data):
    buf = jpype.JArray(jpype.JByte)(len(data))
    for i, b in enumerate(data):
        buf[i] = (b - 256) if b >= 128 else b
    return buf


for s in seg:
    a = space.getAddress(s['addr'])
    data = open(os.path.join(kit, s['file']), 'rb').read()
    blk = mem.getBlock(a)
    if blk is None:
        blk = mem.createInitializedBlock(s['region'], a, len(data), 0,
                                         monitor, False)
    mem.setBytes(a, jbytes(data))
    blk.setRead(True)
    blk.setWrite(not s['exec'])
    blk.setExecute(bool(s['exec']))
    print('block %-10s 0x%08x  %8d B  %s' % (s['region'], s['addr'],
                                             s['size'],
                                             'x' if s['exec'] else 'rw'))

# --- data types from both layouts (only if this chip ships symbol maps) ---
apply_path = os.path.join(kit, 'wil_apply_globals.py')
have_types = os.path.exists(apply_path) and \
    os.path.exists(os.path.join(kit, 'layout_fw.json'))
if not have_types:
    print('no symbol maps in kit -- loading blocks and code only, no types')
apply_src = open(apply_path).read() if have_types else ''
apply_src = apply_src.replace('\nrun()\n', '\n')
ns = {'currentProgram': currentProgram, 'monitor': monitor,
      'createLabel': createLabel, 'createData': createData,
      'clearListing': clearListing}
exec(compile(apply_src, 'wil_apply_globals.py', 'exec'), ns)

dtm = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()
for image in (('fw', 'ucode') if have_types else ()):
    lay = json.load(open(os.path.join(kit, 'layout_%s.json' % image)))
    used = set()
    labelled = typed = skipped = clash = 0
    entries = [g for g in lay['globals'] if g.get('origin') != 'pointee']
    entries += [g for g in lay['globals'] if g.get('origin') == 'pointee']
    for g in entries:
        addr = space.getAddress(g['addr'])
        if mem.getBlock(addr) is None:
            skipped += 1
            continue
        createLabel(addr, g['name'], True, SourceType.IMPORTED)
        labelled += 1
        try:
            dt = ns['build'](g, dtm, used)
            if dt is None:
                continue
            end = addr.add(max(0, dt.getLength() - 1))
            if mem.getBlock(end) is None:
                skipped += 1
                continue
            if listing.getDefinedData(AddressSet(addr, end), True).hasNext():
                clash += 1
                continue
            createData(addr, dt)
            typed += 1
        except Exception as exc:
            print('%s: %s' % (g['name'], exc))
    print('%-6s globals: %d labelled, %d typed, %d skipped, %d clash'
          % (image, labelled, typed, skipped, clash))

# --- entry + analyse -----------------------------------------------------
# Seed from the reset vector and let auto-analysis discover functions. This is
# clean on images whose code and data share a block (Talyn: ~350 reachable
# functions, no garbage). But the reset vector jumps to a *linker* address
# (e.g. 0x120), unmapped once loaded at the host base, so on some images it
# seeds nothing. In that case only -- few functions found -- fall back to a
# full linear disassembly of the executable blocks (Sparrow: ~2900 functions).
# Full linear disassembly is NOT the default: on mixed code/data blocks it
# mis-decodes data and thrashes the analyzer's body-repair pass.
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet as _AS
fm = currentProgram.getFunctionManager()
entry = space.getAddress(ENTRY)
createLabel(entry, 'reset', True, SourceType.IMPORTED)
disassemble(entry)
print('analysing (ARC code, may take a few minutes)...')
analyzeAll(currentProgram)
if fm.getFunctionCount() < 50:
    print('few functions from the reset vector (%d) -- full-block disassembly'
          % fm.getFunctionCount())
    for s in seg:
        if not s.get('exec'):
            continue
        blk = mem.getBlock(space.getAddress(s['addr']))
        DisassembleCommand(_AS(blk.getStart(), blk.getEnd()), None,
                           True).applyTo(currentProgram, monitor)
    analyzeAll(currentProgram)
fm = currentProgram.getFunctionManager()
print('done: %d functions, %d symbols'
      % (fm.getFunctionCount(),
         currentProgram.getSymbolTable().getNumSymbols()))
