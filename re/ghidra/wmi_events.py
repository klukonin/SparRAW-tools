# SPDX-License-Identifier: AGPL-3.0-or-later
# Map the WMI event path (FW->host) and the dispatcher's callers.
# 1) event senders: a mov of an _EVENTID constant shortly before a bl; the
#    dominant bl target across all event sites is the send-event helper. Each
#    function containing an event-id site is an event producer.
# 2) dispatcher callers: references into the dispatcher span -> mailbox/WMI-rx.
# @category wil6210
# @runtime PyGhidra
import json, os, collections
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd

kit = getScriptArgs()[0]
evs = json.load(open(os.path.join(kit, 'wmi_evs.json')))
id2name = {int(v): n for n, v in evs.items()}
# distinctive events only (structured groups), skip tiny/common values
distinct = {i: n for i, n in id2name.items() if i >= 0x0200}
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()

def scalars(ins):
    out = []
    for i in range(ins.getNumOperands()):
        for obj in ins.getOpObjects(i):
            try: out.append(obj.getValue() & 0xffffffff)
            except Exception: pass
    return out

def next_call(ins, budget=8):
    for _ in range(budget):
        ins = ins.getNext()
        if ins is None: return None
        if ins.getFlowType().isCall():
            fl = ins.getFlows()
            return fl[0].getOffset() if fl and mem.getBlock(fl[0]) is not None else None
    return None

# collect event-id sites
sites = []      # (event_id, site_addr, call_target)
it = listing.getInstructions(True)
while it.hasNext():
    ins = it.next()
    ids = [v for v in scalars(ins) if v in distinct]
    if not ids: continue
    t = next_call(ins)
    if t is not None:
        sites.append((ids[0], ins.getAddress().getOffset(), t))

tf = collections.Counter(t for _, _, t in sites)
send = tf.most_common(1)[0][0] if tf else None
print('event-id sites: %d ; candidate send-event helper: 0x%06x (x%d)'
      % (len(sites), send or 0, tf[send] if send else 0))

# label send-event helper, and each producer function by its event
if send is not None:
    createLabel(sp.getAddress(send), 'wmi_send_event', False,
                SourceType.USER_DEFINED)
prod = {}
for eid, site, t in sites:
    if t != send:  # only the sites that actually call the send helper
        continue
    f = fm.getFunctionContaining(sp.getAddress(site))
    fa = f.getEntryPoint().getOffset() if f else site
    prod.setdefault(eid, fa)

rows = []
for eid, fa in sorted(prod.items()):
    name = id2name[eid]
    nm = 'wmi_evt_%s' % name[4:-8].lower()   # WMI_X_EVENTID -> wmi_evt_x
    createLabel(sp.getAddress(fa), nm, False, SourceType.USER_DEFINED)
    rows.append((eid, name, fa, nm))
with open(os.path.join(kit, 'wmi_events.txt'), 'w') as fh:
    fh.write('# wmi_send_event = 0x%06x\n' % (send or 0))
    for eid, name, fa, nm in rows:
        fh.write('0x%04x  %-42s producer=0x%06x  %s\n' % (eid, name, fa, nm))
print('event producers labelled: %d' % len(rows))
for eid, name, fa, nm in rows[:24]:
    print('  0x%04x %-40s @ 0x%06x' % (eid, name, fa))

# dispatcher callers: refs into 0x8de070..0x8dec66
DLO, DHI = 0x8de070, 0x8dec66
refmgr = currentProgram.getReferenceManager()
callers = set()
a = sp.getAddress(DLO)
while a.getOffset() <= DHI:
    for r in refmgr.getReferencesTo(a):
        fr = r.getFromAddress()
        if not (DLO <= fr.getOffset() <= DHI):
            f = fm.getFunctionContaining(fr)
            callers.add(f.getEntryPoint().getOffset() if f else fr.getOffset())
    a = a.add(1)
print('\ndispatcher callers (mailbox/WMI-rx candidates): %d' % len(callers))
for c in sorted(callers)[:10]:
    createLabel(sp.getAddress(c), 'wmi_rx_caller_%06x' % c, False,
                SourceType.USER_DEFINED)
    print('  0x%06x' % c)
