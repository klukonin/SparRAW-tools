# SPDX-License-Identifier: AGPL-3.0-or-later
# Broad even-coverage pass: for representative handlers of uncovered subsystems,
# decompile and name the dominant real worker.
# @category wil6210
# @runtime PyGhidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
INFRA=set('fw_log_trace0 fw_log_trace1 fw_log_trace2 fw_log_trace3 fw_assert fw_assert_wrap wmi_send_event wmi_cmd_reply sta_lookup fw_find_ctx_by_id fw_read_tsf fw_delay fw_post_work sm_post_event sm_step sm_queue_pop fw_nop_stub fw_get_time wmi_emit_event mgmt_alloc_frame'.split())
def nm(off):
    a=sp.getAddress(off) if isinstance(off,int) else off
    f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==(off if isinstance(off,int) else a.getOffset()): return f.getName()
    ss=st.getSymbols(a); return ss[0].getName() if ss else 'FUN_%06x'%(off if isinstance(off,int) else a.getOffset())
# subsystem -> representative handler
reps={'bf':'wmi_h_bf_control','scan':'wmi_h_discovery_start','rfsector':'wmi_h_set_selected_rf_sector_index',
      'cca':'wmi_h_get_cca_indications','sched':'wmi_h_scheduling_scheme','pcp':'wmi_h_get_pcp_channel',
      'newsta':'wmi_h_new_sta','sw_tx':'wmi_h_sw_tx_req'}
for sub,h in reps.items():
    s=st.getGlobalSymbols(h)
    if not s: print('%-10s %s: not found'%(sub,h)); continue
    f=fm.getFunctionAt(s[0].getAddress())
    workers=[]
    for c in f.getCalledFunctions(mon):
        n=c.getName()
        if n in INFRA or n.startswith(('wmi_','sm','fw_','mgmt_','thunk','sta_','conn_')): continue
        if 0x8c01c0<=c.getEntryPoint().getOffset()<0x8c0200: continue
        workers.append((c.getBody().getNumAddresses(),c.getEntryPoint().getOffset()))
    workers.sort(reverse=True)
    w=', '.join('0x%06x(%dB)'%(o,s2) for s2,o in workers[:4])
    print('%-10s %-32s workers: %s'%(sub,h,w or '(thin/inline)'))
