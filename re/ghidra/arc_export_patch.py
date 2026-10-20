# SPDX-License-Identifier: AGPL-3.0-or-later
# Diff the current program's memory against an original .bin and write the
# changed byte runs as an overlay file (addr: hexbytes) consumable by
#   wil_syms.py patch IMAGE.fw --overlay FILE
#
# Args: <original.bin> <segment_base_hex> <out_overlay>
# @category wil6210
# @runtime PyGhidra
import jpype

args = getScriptArgs()
orig = open(args[0], 'rb').read()
base = int(args[1], 16)
out = args[2]
space = currentProgram.getAddressFactory().getDefaultAddressSpace()
mem = currentProgram.getMemory()

# getBytes must fill a real Java byte[]; a Python bytearray comes back a copy
buf = jpype.JArray(jpype.JByte)(len(orig))
got = mem.getBytes(space.getAddress(base), buf)
cur = bytes((buf[i] & 0xff) for i in range(got))

runs = []
i = 0
n = min(len(orig), len(cur))
while i < n:
    if cur[i] != (orig[i] & 0xff):
        j = i
        while j < n and cur[j] != (orig[j] & 0xff):
            j += 1
        runs.append((base + i, cur[i:j]))
        i = j
    else:
        i += 1
with open(out, 'w') as fh:
    for addr, data in runs:
        fh.write('0x%08x: %s\n' % (addr, data.hex()))
print('read %d bytes, changed runs: %d, changed bytes: %d -> %s'
      % (got, len(runs), sum(len(d) for _, d in runs), out))
