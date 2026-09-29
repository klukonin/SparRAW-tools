# SPDX-License-Identifier: AGPL-3.0-or-later
# Apply behaviour-based names to the WMI helpers and the globals they touch.
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
st = currentProgram.getSymbolTable()

FUN = {   # addr -> (name, note)
  0x8dc6c0: 'fw_log_trace',      # writes the trace ring @0x843914
  0x8e90d0: 'fw_read_tsf',       # reads TSF regs @0x886eb8/bc
  0x8e50d4: 'wmi_cmd_reply',     # sends a completion event via wmi_send_event
  0x8c01d8: 'fw_nop_stub',       # returns immediately
}
DAT = {   # data addr -> name
  0x843900: 'g_fw_log_write_ptr',
  0x843904: 'g_fw_log_module_enable',
  0x843914: 'g_fw_log_ring',
  0x886eb4: 'g_tsf_status',
  0x886eb8: 'g_tsf_low',
  0x886ebc: 'g_tsf_high',
}

def clear_helper_labels(off):
    for s in st.getSymbols(sp.getAddress(off)):
        if s.getName().startswith('wmi_helper_'):
            s.delete()

for off, nm in FUN.items():
    a = sp.getAddress(off)
    clear_helper_labels(off)
    f = fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset() == off:
        f.setName(nm, SourceType.USER_DEFINED)
    else:
        createLabel(a, nm, True, SourceType.USER_DEFINED)
    print('func 0x%06x -> %s' % (off, nm))

for off, nm in DAT.items():
    createLabel(sp.getAddress(off), nm, True, SourceType.USER_DEFINED)
    print('data 0x%06x -> %s' % (off, nm))

# re-export the full wmi_* + fw_* map
rows = sorted(set((s.getAddress().getOffset(), s.getName())
                  for s in st.getAllSymbols(False)
                  if s.getName().startswith(('wmi_', 'fw_log', 'fw_read',
                                             'fw_nop', 'g_fw_log', 'g_tsf'))))
import os
with open(os.path.join(getScriptArgs()[0], 'sparrow_wmi_map.txt'), 'w') as fh:
    for a, n in rows:
        fh.write('0x%06x  %s\n' % (a, n))
print('map rows: %d' % len(rows))
