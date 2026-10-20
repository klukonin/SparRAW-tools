#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Разбор потока драйверного сборщика ucode-трассировки (debugfs uc_trace).

Формат (патч драйвера 910): последовательность пачек
    u32 magic = 0x474c4355 ("UCLG")
    u32 count            - слов в пачке
    u64 ktime_ns         - момент чтения на хосте
    u32 words[count]     - слова кольца в порядке записи

В отличие от снимков кольца, поток непрерывен: драйвер опрашивает кольцо
(256 слов, ~1.5 с истории) каждые uc_trace_ms и берёт только новое.

Использование:
    wil_uc_collect.py uc_trace.bin -s tools/fwlog-strings/ucode-4.1.0.1000.bin
    wil_uc_collect.py uc_trace.bin -s ... --raw | tail -40
"""
import argparse, struct, sys

MAGIC = 0x474c4355
# В формате 6.2 (слово времени за заголовком) биты 18..25 заголовка — старший
# байт отметки времени, а НЕ модуль/уровень: логгеры 6.2 (uc_log__emit1..3,
# fw_log_emit*) проверяют модуль/уровень по таблице разрешений и в запись их
# не кладут. Поэтому для 6.2 модуль/уровень печатаются как «-».
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


def batches(blob):
    """Найти пачки. Буфер кольцевой, поэтому начало может быть обрезано:
    ищем первый magic и идём от него."""
    i = 0
    n = len(blob)
    while i + 16 <= n:
        magic, cnt = struct.unpack_from('<II', blob, i)
        if magic != MAGIC or cnt == 0 or cnt > 256 or i + 16 + cnt * 4 > n:
            i += 4
            continue
        ts, = struct.unpack_from('<Q', blob, i + 8)
        words = struct.unpack_from('<%dI' % cnt, blob, i + 16)
        yield ts, words
        i += 16 + cnt * 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dump')
    ap.add_argument('--strings', '-s', required=True)
    ap.add_argument('--raw', action='store_true', help='печатать все записи')
    ap.add_argument('--tail', type=int, default=30)
    ap.add_argument('--since', type=float, help='брать пачки с ktime >= SINCE (с, монотонные часы узла, как /proc/uptime)')
    ap.add_argument('--until', type=float, help='брать пачки с ktime <= UNTIL (с)')
    ap.add_argument('--fwts', action='store_true',
                    help='6.2: печатать метку времени самой записи (слово за '
                         'заголовком) вместо времени пачки на хосте')
    a = ap.parse_args()

    tab = open(a.strings, 'rb').read()
    blob = open(a.dump, 'rb').read()

    stream, times, nb = [], [], 0
    # Буфер драйвера (патч 910) кольцевой, 1 МБ, чтение его НЕ освобождает:
    # каждый снимок содержит всю накопленную историю. Окно опыта задавать
    # только по времени пачек (--since/--until), а не «слить и подождать».
    for ts, words in batches(blob):
        if a.since is not None and ts / 1e9 < a.since:
            continue
        if a.until is not None and ts / 1e9 > a.until:
            continue
        nb += 1
        times.append((len(stream), ts))
        stream.extend(words)

    def parse(ts):
        # ts=1: за заголовком слово метки времени (6.2), ts=0 — формат 4.1;
        # старшая тетрада заголовка в обеих версиях одинакова
        rows, i = [], 0
        while i < len(stream):
            w = stream[i]
            txt = str_at(tab, w & 0xfffff)
            if txt:
                npar = (w >> 26) & 3
                rows.append((i, (w >> 20) & 0xf, (w >> 24) & 3, txt,
                             stream[i + 1 + ts:i + 1 + ts + npar]))
                i += 1 + ts + npar
            else:
                i += 1
        return rows

    # формат выбираем по метке времени: в 6.2 слово за заголовком растёт
    # от записи к записи (см. wil_fw_log.pick_ts)
    ts1 = [stream[r[0] + 1] for r in parse(1) if r[0] + 1 < len(stream)]
    up = sum(1 for a, b in zip(ts1, ts1[1:]) if 0 <= b - a < 0x1000000)
    has_ts = len(ts1) >= 8 and up > 0.8 * (len(ts1) - 1)
    rows = parse(1 if has_ts else 0)

    span = (times[-1][1] - times[0][1]) / 1e9 if len(times) > 1 else 0
    print('# пачек %d, слов %d, записей %d, время %.1f с' % (nb, len(stream), len(rows), span))

    def ts_of(idx):
        t = times[0][1]
        for start, v in times:
            if start > idx:
                break
            t = v
        return t

    show = rows if a.raw else rows[-a.tail:]
    t0 = times[0][1] if times else 0
    for idx, mod, lvl, txt, args in show:
        arg = ''
        if args:
            out = []
            for x in args:
                if (x >> 24) == 1:
                    t = str_at(tab, x & 0xffffff)
                    out.append(t if t else '0x%x' % x)
                else:
                    out.append('0x%x' % x)
            try:
                arg = ' ' + (txt % tuple(args)) if txt.count('%') - 2 * txt.count('%%') == len(args) else ' | ' + ' '.join(out)
            except Exception:
                arg = ' | ' + ' '.join(out)
        line = (txt % tuple(args)) if arg.startswith(' ' + txt[:4]) else txt + arg
        if a.fwts and has_ts:
            # метка ucode 6.2 — младшие 32 бита TSF в мкс; у STA TSF
            # синхронизирован с AP по маякам, поэтому трассы сводятся
            print('%10d %-9s %-4s %s' % (stream[idx + 1], '-' if has_ts else MODULES[mod], '-' if has_ts else LEVELS[lvl], line.strip()[:110]))
        else:
            print('%9.3f %-9s %-4s %s' % ((ts_of(idx) - t0) / 1e9, '-' if has_ts else MODULES[mod], '-' if has_ts else LEVELS[lvl], line.strip()[:110]))


if __name__ == '__main__':
    main()
