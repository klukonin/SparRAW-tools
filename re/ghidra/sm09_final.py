# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable()
def setfun(off,nm):
    a=sp.getAddress(off)
    if fm.getFunctionContaining(a) is None: CreateFunctionCmd(a).applyTo(currentProgram)
    f=fm.getFunctionContaining(a)
    if f and f.getEntryPoint().getOffset()==off and f.getName().startswith(('FUN_','sm09_act')):
        f.setName(nm,SourceType.USER_DEFINED)
FUN={
 0x8c2094:'sm09_connect_begin',   # schedule work + arm 2 timers
 0x8c2210:'sm09_step_advance',    # finish item, dequeue next from sta+0x18
 0x8c22f0:'sm09_step_s2',
 0x8c2358:'sm09_step_s3',         # arms timer 0x90c8
 0x8c2158:'sm09_step_s4',
 0x8c2310:'sm09_connect_abort',   # sta_notify_connect + cleanup
 0x8c1fd0:'sm09_timer0_refresh',
 0x8c2004:'sm09_timer1_refresh',
 0x8c2078:'sm09_set_timeout',
 # timer callbacks / work
 0x8e551c:'sm09_connect_work',    # fw_post_work(0x2151c)
 0x8e3fac:'sm09_timer0_cb',       # fw_timer_arm(0x23fac)
 0x8e3fd4:'sm09_timer1_cb',       # fw_timer_arm(0x23fd4)
 0x8c90c8:'sm09_timer2_cb',       # fw_timer_arm(0x90c8)
}
for off,nm in FUN.items(): setfun(off,nm)
setPreComment(sp.getAddress(0x902b70),
 'SM09 per-STA connect handshake (module 0x29, driven by SM02 via sta+0x80). '
 'S0=IDLE S1=STARTED S2..S5=step queue (sta+0x18) processing S6=special. '
 'E0=start E1..E5=step-done(advance) E6=abort(notify+cleanup) E7=timer refresh. '
 'begin arms 2 timers + schedules sm09_connect_work; abort calls sta_notify_connect.')
import os
rows=sorted(set((s.getAddress().getOffset(),s.getName()) for s in st.getAllSymbols(False)
   if s.getName().startswith(('wmi_','fw_','sta_','sm_','sm0','sm1','g_','connect_','link_'))))
open(os.path.join(getScriptArgs()[0],'sparrow_wmi_map.txt'),'w').write(
   ''.join('0x%06x  %s\n'%(a,n) for a,n in rows))
print('map rows: %d'%len(rows))
