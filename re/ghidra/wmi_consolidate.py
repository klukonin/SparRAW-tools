# SPDX-License-Identifier: AGPL-3.0-or-later
# Consolidate the WMI map: authoritative send-event label, name the WMI-rx
# task (function containing the dispatcher), and dump a combined symbol map.
# @category wil6210
# @runtime PyGhidra
import os
from ghidra.program.model.symbol import SourceType, SymbolType
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
st = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()
kit = os.path.dirname(os.path.abspath(getScriptArgs()[0])) if getScriptArgs() else '.'
kit = getScriptArgs()[0]

# 1) authoritative: 0x8e48ec is wmi_send_event, not a command handler
send = sp.getAddress(0x8e48ec)
for s in st.getSymbols(send):
    if s.getName().startswith('wmi_h_'):
        s.delete()
createLabel(send, 'wmi_send_event', True, SourceType.USER_DEFINED)

# 2) name the WMI-rx task: the function containing the dispatcher entry
disp = sp.getAddress(0x8de070)
f = fm.getFunctionContaining(disp)
if f is None:
    # create one at the nearest instruction start walking back to a prologue
    from ghidra.app.cmd.function import CreateFunctionCmd
    CreateFunctionCmd(disp).applyTo(currentProgram)
    f = fm.getFunctionContaining(disp)
if f is not None:
    f.setName('wmi_rx_task', SourceType.USER_DEFINED)
    print('WMI-rx task: %s @ %s' % (f.getName(), f.getEntryPoint()))
createLabel(disp, 'wmi_dispatch', True, SourceType.USER_DEFINED)

# 3) dump every wmi_* label we have applied
rows = []
for s in st.getAllSymbols(False):
    n = s.getName()
    if n.startswith('wmi_'):
        rows.append((s.getAddress().getOffset(), n))
rows = sorted(set(rows))
with open(os.path.join(kit, 'sparrow_wmi_map.txt'), 'w') as fh:
    for a, n in rows:
        fh.write('0x%06x  %s\n' % (a, n))
by = {}
for a, n in rows:
    key = n.split('_')[1] if '_' in n else n
    by[key] = by.get(key, 0) + 1
print('total wmi_* labels: %d' % len(rows))
print('breakdown: %s' % ', '.join('%s=%d' % kv for kv in sorted(by.items())))
