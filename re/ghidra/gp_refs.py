# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Разбор gp-относительных обращений в абсолютные адреса.
# gp устанавливается один раз: в fw_code 0x800170 (на 0x8c0268),
# в ucode 0x800528 (на 0x9201b8). Ghidra этого не знает, поэтому в
# декомпиляциях висят unaff_gp + смещение.
import re
GP_FW, GP_UC = 0x800170, 0x800528
lst = currentProgram.getListing()
pat = re.compile(r'\[gp,\s*(-?0x[0-9a-fA-F]+|-?\d+)\]')
it = lst.getInstructions(True)
rows = []
while it.hasNext():
    i = it.next()
    m = pat.search(str(i))
    if not m:
        continue
    d = int(m.group(1), 16) if 'x' in m.group(1) else int(m.group(1))
    a = i.getAddress().getOffset()
    base = GP_FW if a < 0x900000 else GP_UC
    op = str(i).split()[0]
    rows.append((a, base + d, op, str(i)))
print("GPREFS %d" % len(rows))
for a, abs_, op, s in rows:
    print("GPREF %06x %06x %-8s %s" % (a, abs_, op, s))
