#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Поиск связей между полями разных команд MAC в одной трассе.

Приём, которым расшифрован 0x3f: если значение поля команды A совпадает
со значением поля команды B, стоящей рядом в потоке, значит обе несут
одну и ту же величину.  Так номер сектора нашёлся сразу в двух командах.

Инструмент перебирает пары (код, сдвиг, ширина) и ищет устойчивые
совпадения на соседних командах.

    mac_cmd_fieldlink.py трасса.bin ... [--window 6] [--min 8]
"""
import argparse, collections, importlib.util, struct, sys

FIELDS = [(sh, w) for sh in range(0, 20, 2) for w in (4, 6, 8, 9, 10, 12)
          if sh + w <= 24]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dumps', nargs='+')
    ap.add_argument('--window', type=int, default=6)
    ap.add_argument('--min', type=int, default=8)
    a = ap.parse_args()

    spec = importlib.util.spec_from_file_location('m', 'tools/wil_mac_ring.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    st = []
    for f in a.dumps:
        b = open(f, 'rb').read()
        sn = [list(struct.unpack('<256I', b[i * 1024:(i + 1) * 1024]))
              for i in range(len(b) // 1024)]
        prev = sn[0]
        for cur in sn[1:]:
            w = m.window(prev, cur)
            if w and w[2]:
                st += [cur[(w[0] + j) % 256] for j in range(w[1])
                       if prev[(w[0] + j) % 256] != cur[(w[0] + j) % 256]]
            prev = cur

    # поле, принимающее одно значение, совпадает с чем угодно по случайности;
    # берём только те, что реально меняются
    vary = collections.defaultdict(set)
    for x in st:
        c, p = x >> 24, x & 0xffffff
        for sh, w in FIELDS:
            vary[(c, sh, w)].add((p >> sh) & ((1 << w) - 1))

    hit = collections.Counter()
    tot = collections.Counter()
    for i, x in enumerate(st):
        ca, pa = x >> 24, x & 0xffffff
        for j in range(i + 1, min(i + 1 + a.window, len(st))):
            y = st[j]
            cb, pb = y >> 24, y & 0xffffff
            if ca == cb:
                continue
            for sa, wa in FIELDS:
                if len(vary[(ca, sa, wa)]) < 3:
                    continue
                va = (pa >> sa) & ((1 << wa) - 1)
                if va == 0:
                    continue
                for sb, wb in FIELDS:
                    if len(vary[(cb, sb, wb)]) < 3:
                        continue
                    vb = (pb >> sb) & ((1 << wb) - 1)
                    key = (ca, sa, wa, cb, sb, wb)
                    tot[key] += 1
                    if va == vb:
                        hit[key] += 1

    out = []
    for key, n in hit.items():
        t = tot[key]
        if n >= a.min and n / t > 0.9:
            out.append((n, key))
    out.sort(reverse=True)
    seen = set()
    print('# устойчивые совпадения полей (доля > 90%%, не менее %d наблюдений)'
          % a.min)
    for n, (ca, sa, wa, cb, sb, wb) in out[:40]:
        k = (ca, cb)
        if k in seen:
            continue
        seen.add(k)
        print('0x%02x[%d:%d] == 0x%02x[%d:%d]   %d раз'
              % (ca, sa + wa - 1, sa, cb, sb + wb - 1, sb, n))


if __name__ == '__main__':
    main()
