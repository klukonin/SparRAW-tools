# SPDX-License-Identifier: AGPL-3.0-or-later
# WMI dispatcher -> handlers, refined.
# Within the bounded dispatcher, each case: cmp id / bne next / <body> / b tail.
# The body may call a shared prologue helper (0x8dc6c0 etc., called by many
# cases) AND the command-specific handler. We collect every call in the case
# body and pick the RAREST target across the whole dispatcher as the handler;
# helpers, being called by many cases, are dropped. Cases whose only calls are
# shared helpers are left unnamed (handled inline / trivial) but commented.
# @category wil6210
# @runtime PyGhidra
import json, os, collections
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd

kit = getScriptArgs()[0]
cmds = json.load(open(os.path.join(kit, 'wmi_cmds.json')))
id2name = {int(v): n for n, v in cmds.items()}
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
TAIL = 0x8dec72

# bound dispatcher
lo = hi = None
it = listing.getInstructions(True)
while it.hasNext():
    ins = it.next(); fl = ins.getFlows()
    if fl and any(f.getOffset() == TAIL for f in fl):
        o = ins.getAddress().getOffset()
        lo = o if lo is None else min(lo, o); hi = o if hi is None else max(hi, o)

def scalars(ins):
    out = []
    for i in range(ins.getNumOperands()):
        for obj in ins.getOpObjects(i):
            try: out.append(obj.getValue() & 0xffffffff)
            except Exception: pass
    return out

def body_calls(addr, stop_off, budget=24):
    """All call targets from addr until a branch to tail or budget."""
    outs = []
    ins = listing.getInstructionAt(addr)
    for _ in range(budget):
        if ins is None: break
        ft = ins.getFlowType(); fl = ins.getFlows()
        if fl and any(f.getOffset() == TAIL for f in fl): break
        if ft.isCall() and fl and mem.getBlock(fl[0]) is not None:
            outs.append(fl[0].getOffset())
        ins = ins.getNext()
    return outs

# pass 1: gather per-case candidate call lists
cases = []   # (id, [call targets])
ins = listing.getInstructionAt(sp.getAddress(lo - 0x80))
while ins is not None and ins.getAddress().getOffset() <= hi:
    ids = [v for v in scalars(ins) if v in id2name]
    if ids:
        v = ids[0]; cur = ins.getNext()
        for _ in range(4):
            if cur is None: break
            ft = cur.getFlowType(); fl = cur.getFlows()
            if ft.isJump() and ft.isConditional() and fl:
                cases.append((v, body_calls(fl[0], TAIL))); break
            if ft.isCall() and fl and mem.getBlock(fl[0]) is not None:
                cases.append((v, body_calls(ins.getNext().getAddress(), TAIL)
                              or [fl[0].getOffset()])); break
            cur = cur.getNext()
    ins = ins.getNext()

# frequency of each call target across all cases -> helpers are frequent
freq = collections.Counter(t for _, ts in cases for t in ts)
HELPER = {t for t, c in freq.items() if c >= 4}     # called by >=4 cases

results = {}
for v, ts in cases:
    cand = [t for t in ts if t not in HELPER]
    if cand:
        # rarest, then earliest
        cand.sort(key=lambda t: (freq[t], t))
        results.setdefault(v, cand[0])

print('dispatcher 0x%06x..0x%06x  cases:%d  helpers:%d  handlers:%d'
      % (lo, hi, len(cases), len(HELPER), len(results)))
print('shared helpers: %s' % ', '.join('0x%06x(x%d)' % (t, freq[t])
                                        for t in sorted(HELPER)))

# label dispatcher + helpers + handlers
createLabel(sp.getAddress(lo - 0x80 if lo else lo), 'wmi_dispatch', False,
            SourceType.USER_DEFINED)
for i, t in enumerate(sorted(HELPER)):
    createLabel(sp.getAddress(t), 'wmi_helper_%d' % i, False,
                SourceType.USER_DEFINED)
rows = []
for v, haddr in sorted(results.items()):
    name = id2name[v]; a = sp.getAddress(haddr)
    hn = 'wmi_h_%s' % name[4:-6].lower()
    createLabel(a, hn, False, SourceType.USER_DEFINED)
    if currentProgram.getFunctionManager().getFunctionContaining(a) is None:
        CreateFunctionCmd(a).applyTo(currentProgram)
    rows.append((v, name, haddr, hn))
with open(os.path.join(kit, 'wmi_handlers.txt'), 'w') as fh:
    fh.write('# WMI dispatcher 0x%06x..0x%06x\n' % (lo, hi))
    for v, name, haddr, hn in rows:
        fh.write('0x%04x  %-42s 0x%06x  %s\n' % (v, name, haddr, hn))
uniq = len(set(h for _, h in results.items()))
print('unique handler addresses: %d' % uniq)
for v, name, haddr, hn in rows:
    print('  0x%04x %-40s -> 0x%06x' % (v, name, haddr))
