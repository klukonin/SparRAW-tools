# Имена функций Talyn из таблиц строк журнала (записи 0x64 = uc, 0x65 = fw образа .fw).
# Ссылки в коде: limm 0x01000000|offset. База смещения подбирается автоматически.
import sys, re, struct, collections
fw, listing, kind, out = sys.argv[1:5]
b = open(fw,'rb').read(); o = 0; recs = {}
while o + 8 <= len(b):
    t, fl, sz = struct.unpack_from('<HHI', b, o)
    if o + 8 + sz > len(b): break
    recs.setdefault(t, b[o+8:o+8+sz]); o = (o + 8 + sz + 3) & ~3
tab = recs.get(0x65 if kind == 'fw' else 0x64)
if tab is None: sys.exit('нет таблицы строк')
starts = {}
i = 0
while i < len(tab):
    j = tab.find(b'\0', i)
    if j < 0: break
    s = tab[i:j]
    if len(s) >= 4 and all(32 <= c < 127 for c in s): starts[i] = s.decode()
    i = j + 1
refs = []  # (addr, func, value)
pat = re.compile(r'0x(1[0-9a-f]{6})\b')
for line in open(listing):
    p = line.rstrip('\n').split('\t')
    if len(p) < 3: continue
    for m in pat.finditer(p[1]):
        v = int(m.group(1), 16)
        if 0x1000000 <= v < 0x1000000 + len(tab) + 0x100: refs.append((p[0], p[2], v & 0xffffff))
best = max(range(-64, 65, 4), key=lambda d: sum(1 for _,_,v in refs if (v + d) in starts))
hits = [(a, f, starts[v + best]) for a, f, v in refs if (v + best) in starts]
print('строк', len(starts), 'ссылок', len(refs), 'база', best, 'попаданий', len(hits))
byf = collections.defaultdict(list)
for a, f, s in hits:
    if f: byf[f].append(s)
def nm(s):
    s = re.sub(r'%[-0-9.lhx]*[a-zA-Z]', '', s); w = re.findall(r'[A-Za-z][A-Za-z0-9_]+', s)
    return '_'.join(w[:4])[:48] or 'str'
with open(out, 'w') as f:
    f.write('# %s %s: функция  число_строк  предлагаемое_имя | первая строка\n' % (fw.split('/')[-1], kind))
    for fn, ss in sorted(byf.items()):
        files = [s for s in ss if s.endswith(('.cpp', '.c', '.h'))]
        txt = [s for s in ss if s not in files]
        name = nm(txt[0]) if txt else nm(files[0])
        f.write('%s\t%d\t%s\t| %s %s\n' % (fn, len(ss), name, (txt or ss)[0][:90], ('[' + files[0].split('/')[-1] + ']') if files else ''))
print('функций с именами', len(byf))
