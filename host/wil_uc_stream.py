#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Склейка потока ucode-лога из последовательности снимков кольца.

Кольцо короткое (256 слов, ~1.5 с истории), поэтому одиночный снимок рвёт
последовательность. Но у кольца есть монотонный индекс записи (write_ptr),
и если снимать чаще, чем оно переполняется, соседние снимки сшиваются:
из каждого берём слова с позиций [prev_wptr, cur_wptr) — они ещё не затёрты.

Порядок внутри записи (из декомпиляции логгера 0x925548): СНАЧАЛА слово-
заголовок, затем его аргументы; индекс сдвигается на 1+N.

Использование:
    wil_uc_stream.py 'снимки/*.bin' --strings tools/fwlog-strings/ucode-4.1.0.1000.bin
"""
import argparse, glob, struct, sys

RING_OFF = 0x209c - 0x800000 + 0x800000  # адрес кольца задаётся параметром
MODULES = ['SYSTEM', 'TX', 'RX', 'ISR', 'BCON', 'BEAMFORM', 'UC6', 'UC7',
           'UC8', 'UC9', 'UC10', 'UC11', 'UC12', 'UC13', 'UC14', 'UC15']
LEVELS = ['ERR', 'WARN', 'INFO', 'VERB']


def str_at(tab, off):
    if off <= 0 or off >= len(tab) or tab[off - 1] != 0:
        return None
    end = tab.find(b'\x00', off)
    s = tab[off:end if end >= 0 else len(tab)]
    if len(s) < 3 or not all(32 <= c < 127 or c == 9 for c in s):
        return None
    return s.decode('latin1')


def stitch(files, ring_off, entries=256):
    """Собрать непрерывный поток слов из снимков."""
    stream, prev = [], None
    lost = 0
    for f in files:
        d = open(f, 'rb').read()
        if len(d) < ring_off + 0x14 + entries * 4:
            continue
        wptr = struct.unpack_from('<I', d, ring_off)[0]
        ring = [struct.unpack_from('<I', d, ring_off + 0x14 + i * 4)[0]
                for i in range(entries)]
        if prev is None:
            prev = max(0, wptr - entries)
        if wptr - prev > entries:          # не успели — часть затёрлась
            lost += wptr - prev - entries
            prev = wptr - entries
        for k in range(prev, wptr):
            stream.append(ring[k % entries])
        prev = wptr
    return stream, lost


def parse(stream, tab):
    rows, i = [], 0
    while i < len(stream):
        w = stream[i]
        txt = str_at(tab, w & 0xfffff)
        if txt:
            n = (w >> 26) & 3
            rows.append(((w >> 20) & 0xf, (w >> 24) & 3, txt, stream[i + 1:i + 1 + n]))
            i += 1 + n
        else:
            i += 1
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pattern')
    ap.add_argument('--strings', '-s', required=True)
    ap.add_argument('--addr', '-a', default='0x80209c')
    ap.add_argument('--base', default='0x800000')
    ap.add_argument('--raw', action='store_true', help='печатать весь поток')
    a = ap.parse_args()

    files = sorted(glob.glob(a.pattern))
    tab = open(a.strings, 'rb').read()
    ring_off = int(a.addr, 16) - int(a.base, 16)
    stream, lost = stitch(files, ring_off)
    rows = parse(stream, tab)
    print('# снимков %d, слов в потоке %d, потеряно %d, записей %d'
          % (len(files), len(stream), lost, len(rows)))
    if a.raw:
        for m, l, t, args in rows:
            arg = ' | ' + ' '.join('0x%x' % x for x in args) if args else ''
            print('%-9s %-4s %s%s' % (MODULES[m], LEVELS[l], t.strip()[:90], arg))
    return rows


if __name__ == '__main__':
    main()
