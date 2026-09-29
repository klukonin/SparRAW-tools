#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Поиск ячеек памяти устройства по серии снимков — как в ArtMoney.

Работает с дампами штатных debugfs blob_* (без патчей). Четыре фильтра:

    increased   значение выросло
    decreased   уменьшилось
    changed     изменилось (как угодно)
    unchanged   не изменилось

Смысл в СЕРИИ: каждый следующий фильтр применяется к уже суженному
множеству кандидатов, поэтому случайные совпадения отсеиваются. Для
величины, которая должна следовать за параметром, самый сильный фильтр —
монотонность по всей серии (`--monotonic`), он отсекает шум лучше, чем
любое одиночное сравнение.

    wil_memscan.py --blob blob_uc_data --base 0x800000 \
        снимок1 снимок2 снимок3 --monotonic up
    wil_memscan.py ... --filter changed --filter unchanged
"""
import argparse, struct, sys


def words(buf, width):
    fmt = {16: '<H', 32: '<I'}[width]
    step = width // 8
    return [struct.unpack_from(fmt, buf, o)[0]
            for o in range(0, len(buf) - step + 1, step)], step


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dumps', nargs='+', help='снимки в порядке роста параметра')
    ap.add_argument('--base', default='0x800000')
    ap.add_argument('--width', type=int, default=32, choices=(16, 32))
    ap.add_argument('--monotonic', choices=('up', 'down'))
    ap.add_argument('--filter', action='append', default=[],
                    choices=('increased', 'decreased', 'changed', 'unchanged'),
                    help='по одному на каждый переход между снимками')
    ap.add_argument('--ratio', type=float,
                    help='оставить только растущие в это число раз за шаг')
    ap.add_argument('--min', type=int, default=8, help='отбросить мелкие значения')
    ap.add_argument('--limit', type=int, default=40)
    a = ap.parse_args()
    base = int(a.base, 16)

    series = []
    for f in a.dumps:
        w, step = words(open(f, 'rb').read(), a.width)
        series.append(w)
    n = min(len(s) for s in series)
    cand = {i for i in range(n) if series[0][i] >= a.min}

    if a.monotonic:
        for k in range(len(series) - 1):
            x, y = series[k], series[k + 1]
            cand = {i for i in cand
                    if (y[i] > x[i] if a.monotonic == 'up' else y[i] < x[i])}
    for k, f in enumerate(a.filter):
        if k + 1 >= len(series):
            break
        x, y = series[k], series[k + 1]
        test = {'increased': lambda i: y[i] > x[i],
                'decreased': lambda i: y[i] < x[i],
                'changed':   lambda i: y[i] != x[i],
                'unchanged': lambda i: y[i] == x[i]}[f]
        cand = {i for i in cand if test(i)}
    if a.ratio:
        for k in range(len(series) - 1):
            x, y = series[k], series[k + 1]
            cand = {i for i in cand
                    if x[i] and abs(y[i] / x[i] - a.ratio) < 0.02}

    out = sorted(cand)
    print('# кандидатов: %d (из %d слов, ширина %d бит)' % (len(out), n, a.width))
    for i in out[:a.limit]:
        vals = '  '.join('%d' % s[i] for s in series)
        print('0x%06x  %s' % (base + i * (a.width // 8), vals))
    if len(out) > a.limit:
        print('# ... ещё %d' % (len(out) - a.limit))


if __name__ == '__main__':
    main()
