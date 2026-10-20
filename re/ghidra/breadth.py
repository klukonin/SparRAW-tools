# SPDX-License-Identifier: AGPL-3.0-or-later
# Broaden the map safely: name connect_setup, then for each wmi_h_* handler
# with exactly ONE non-infrastructure callee, label that callee <handler>_impl.
# Infrastructure is excluded so we never mislabel a logger/asserter as a worker.
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
mon=ConsoleTaskMonitor()

# confident manual names first
man={0x8ccdf4:'connect_setup', 0x8e9edc:'sta_notify_connect'}
for off,nm in man.items():
    f=fm.getFunctionContaining(sp.getAddress(off))
    if f and f.getEntryPoint().getOffset()==off: f.setName(nm,SourceType.USER_DEFINED)

def pname(f):
    return f.getName()

INFRA=set(['fw_log_trace0','fw_log_trace1','fw_log_trace2','fw_log_trace3',
  'fw_assert','fw_assert_wrap','wmi_send_event','wmi_cmd_reply','sta_lookup',
  'fw_find_ctx_by_id','fw_read_tsf','fw_delay','fw_post_work','sm_post_event',
  'sm_step','sm_queue_pop','fw_nop_stub'])

# collect handler entry points
handlers=[]
for s in st.getAllSymbols(False):
    if s.getName().startswith('wmi_h_'):
        f=fm.getFunctionAt(s.getAddress())
        if f: handlers.append((s.getName(), f))

named=0; ambiguous=[]
for hn, f in handlers:
    callees=[c for c in f.getCalledFunctions(mon)]
    workers=[c for c in callees if c.getName() not in INFRA
             and not c.getName().startswith(('wmi_h_','wmi_evt_'))]
    # exclude tiny arg-thunks (0x8c01xx family) and already-named things
    workers=[c for c in workers if not (0x8c01c0<=c.getEntryPoint().getOffset()<0x8c0200)]
    uniq=sorted(set(c.getEntryPoint().getOffset() for c in workers))
    if len(uniq)==1:
        w=fm.getFunctionAt(sp.getAddress(uniq[0]))
        impl='%s_impl'%hn[6:]   # strip wmi_h_
        if w.getName().startswith('FUN_'):
            w.setName(impl, SourceType.USER_DEFINED)
            named+=1
    elif len(uniq)>1:
        ambiguous.append((hn,len(uniq)))
print('handler workers named <x>_impl: %d'%named)
print('ambiguous (multi-worker, manual): %s'%', '.join('%s:%d'%a for a in ambiguous[:20]))

import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','g_','connect_'))
   or s.getName().endswith('_impl')))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
