# @runtime PyGhidra
# Человеческие имена (names/tl_7.5.3.115_<k>_human.tsv): H/M — имя функции, L — только строка в комментарии.
from ghidra.program.model.symbol import SourceType
path = getScriptArgs()[0]
fm = currentProgram.getFunctionManager(); sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
n = c = 0
for l in open(path):
    if l.startswith('#'): continue
    r = l.rstrip('\n').split('\t')
    if len(r) < 5: continue
    a, old, new, conf, ev = r[:5]
    f = fm.getFunctionAt(sp.getAddress(int(a, 16)))
    if f is None: continue
    prev = f.getComment() or ''
    if conf in ('H', 'M'):
        try:
            f.setName(new, SourceType.USER_DEFINED); n += 1
        except Exception as e:
            print('SKIP', a, new, e); continue
        note = 'имя (%s): %s; было %s' % (conf, ev, old)
    else:
        note = 'кандидат (L): %s — %s' % (new, ev)
    f.setComment((prev + '\n' + note).strip()[:800]); c += 1
print('HUMAN NAMES APPLIED', n, 'COMMENTS', c)
