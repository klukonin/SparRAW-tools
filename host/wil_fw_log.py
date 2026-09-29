#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Декодер трассировки прошивки wil6210 (Sparrow).

Как это работает (вскрыто на железе 2026-09-21):

  * Прошивка сама выделяет лог-кольцо и публикует его адрес в
    RGF_USER_USAGE_1 (0x880004); ucode — в RGF_USER_USAGE_2 (0x880008).
    Драйвер эти регистры только обнуляет перед стартом.
  * Пока не заполнены байты уровней в ЗАГОЛОВКЕ кольца, прошивка не пишет
    ничего. Заголовок:
        u32 write_ptr;
        u8  module_level_enable[16];  // b0 err, b1 warn, b2 info, b3 verbose
        u32 evt[];
    Включает их наш патч драйвера 905-wil6210-fw-log-enable:
        echo 7 > /sys/module/wil6210/parameters/fw_log_level  + сброс FW.
  * Запись кольца — слово:
        биты 0..19  — смещение строки в таблице строк образа,
        биты 20..23 — модуль, 24..25 — уровень, 26..27 — число аргументов,
        бит 28      — is_string.
    Аргументы идут СЛЕДОМ за словом-заголовком.
  * Таблица строк лежит в САМОМ ОБРАЗЕ MikroTik: запись типа 101 — строки fw,
    типа 100 — строки ucode. В linux-firmware (5.2) их НЕТ, поэтому
    расшифровка возможна только на прошивке MikroTik (4.1/6.2).

Снять кольцо с устройства:
    cat /sys/kernel/debug/ieee80211/phy0/wil6210/blob_fw_peri > /tmp/peri.bin
    cat /sys/kernel/debug/ieee80211/phy0/wil6210/RGF_USER_USAGE_1   # адрес

Использование:
    wil_fw_log.py peri.bin --strings tools/fwlog-strings/fw-4.1.0.1000.bin \
                  --addr 0x843900 [-n 4096]
    wil_fw_log.py --extract-strings wil6210_4.1.0.1000_stock_raw.fw -o tools/fwlog-strings
"""
import argparse, struct, sys, os

# карта адресов прошивки -> блоб debugfs (Sparrow)
BLOBS = {
    'fw_peri': (0x840000, 0x860000),
    'fw_data': (0x800000, 0x808000),
    'uc_data': (0x800000, 0x804000),   # адреса ucode, блоб blob_uc_data
}
# В формате 6.2 (слово времени за заголовком) биты 18..25 заголовка — старший
# байт отметки времени, а НЕ модуль/уровень: логгеры 6.2 (uc_log__emit1..3,
# fw_log_emit*) проверяют модуль/уровень по таблице разрешений и в запись их
# не кладут. Поэтому для 6.2 модуль/уровень печатаются как «-».
MODULES = ['SYSTEM', 'DRIVERS', 'MAC_MON', 'HOST_CMD', 'PHY_MON', 'INFRA',
           'MOD6', 'MOD7', 'MOD8', 'MOD9', 'MOD10', 'CONN_MGR', 'MOD12',
           'MOD13', 'POWER_MNGR', 'MOD15']
# у ucode своя нумерация модулей (из начала его таблицы строк)
UC_MODULES = ['SYSTEM', 'TX', 'RX', 'ISR', 'BCON', 'BEAMFORM', 'UC6', 'UC7',
              'UC8', 'UC9', 'UC10', 'UC11', 'UC12', 'UC13', 'UC14', 'UC15']
LEVELS = ['ERR', 'WARN', 'INFO', 'VERB']


def str_at(tab, off, strict=True):
    """Строка по смещению в таблице.

    strict: требовать, чтобы смещение указывало на НАЧАЛО строки (перед ним
    нулевой байт). Без этой проверки мусорные слова кольца попадают на середины
    строк и декодер выдаёт правдоподобную чушь вроде 'YSTEM' или 'OST_CMD'.
    """
    if off <= 0 or off >= len(tab):
        return None
    if strict and tab[off - 1] != 0:
        return None
    end = tab.find(b'\x00', off)
    if end < 0:
        end = len(tab)
    s = tab[off:end]
    if len(s) < 4 or not all(32 <= c < 127 or c == 9 for c in s):
        return None
    return s.decode('latin1')


def fmt_args(txt, args, tab):
    """Подставить аргументы. Аргумент-строка приходит как 0x01000000|offset
    (та же кодировка, что у ссылок на строки в коде прошивки)."""
    out = []
    for a in args:
        if (a >> 24) == 1:
            t = str_at(tab, a & 0xffffff)
            out.append(t if t else '0x%x' % a)
        else:
            out.append('0x%x' % a)
    if '%' in txt and len(out) == txt.count('%') - 2 * txt.count('%%'):
        try:
            vals = []
            for a, o in zip(args, out):
                vals.append(o if not o.startswith('0x') else a)
            return txt % tuple(vals)
        except Exception:
            pass
    return txt + (' | ' + ' '.join(out) if out else '')


def extract_strings(fwfile, outdir):
    """Вынуть таблицы строк (записи 100/101) из образа MikroTik."""
    d = open(fwfile, 'rb').read()
    off, n = 0, 0
    while off + 8 <= len(d):
        t, sz = struct.unpack_from('<II', d, off)
        if sz == 0 or off + 8 + sz > len(d):
            break
        if t in (100, 101):
            name = 'ucode' if t == 100 else 'fw'
            p = os.path.join(outdir, '%s-strings.bin' % name)
            open(p, 'wb').write(d[off + 8:off + 8 + sz])
            print('запись %d -> %s (%d Б)' % (t, p, sz))
            n += 1
        off += 8 + sz
    if not n:
        print('таблиц строк в образе нет (linux-firmware их не содержит)')
    return n


def decode_ucode(blob, ring_addr, tab, base=0x800000, entries=256):
    """Кольцо ucode устроено иначе, чем у прошивки (вскрыто декомпиляцией
    логгера 0x925548): по адресу из RGF_USER_USAGE_2 лежит ИНДЕКС записи,
    по +4 — байт разрешения, а сами записи начинаются с +0x14 и их ровно 256
    (индекс берётся по модулю 256). И живёт всё это в ПАМЯТИ ДАННЫХ UCODE
    (blob_uc_data), а не прошивки: у них разные окна на один адрес 0x800000."""
    off = ring_addr - base
    wptr = struct.unpack_from('<I', blob, off)[0]
    enable = blob[off + 4]
    ring = [struct.unpack_from('<I', blob, off + 0x14 + i * 4)[0]
            for i in range(entries)]
    rows, i = [], 0
    while i < entries:
        idx = (wptr + i) % entries
        w = ring[idx]
        txt = str_at(tab, w & 0xfffff)
        if txt:
            npar = (w >> 26) & 3
            rows.append((i, (w >> 20) & 0xf, (w >> 24) & 3, txt,
                         [ring[(idx + 1 + k) % entries] for k in range(npar)]))
            i += 1 + npar
        else:
            i += 1
    return wptr, [enable], rows


def parse_words(words, tab, ts):
    """ts=1: за заголовком идёт слово метки времени (формат 6.2), ts=0 — 4.1."""
    rows, i = [], 0
    while i < len(words):
        w = words[i]
        txt = str_at(tab, w & 0xfffff)
        if txt:
            npar = (w >> 26) & 3
            rows.append((i, (w >> 20) & 0xf, (w >> 24) & 3, txt,
                         words[i + 1 + ts:i + 1 + ts + npar]))
            i += 1 + ts + npar
        else:
            i += 1
    return rows


def decode(blob, base, ring_addr, tab, count):
    off = ring_addr - base
    wptr = struct.unpack_from('<I', blob, off)[0]
    levels = [struct.unpack_from('<I', blob, off + 4 + i * 4)[0] for i in range(4)]
    words = [struct.unpack_from('<I', blob, off + 0x14 + i * 4)[0]
             for i in range(count) if off + 0x14 + i * 4 + 4 <= len(blob)]
    # Старшая тетрада заголовка (0xa/0xb) одинакова в 4.1 и 6.2, но в 6.2
    # за КАЖДЫМ заголовком идёт слово времени. Версию по заголовку не
    # отличить, поэтому смотрим, похожи ли слова за заголовками на растущую
    # метку времени — см. pick_ts.
    global HAS_TS
    HAS_TS = pick_ts(words, tab)
    rows = parse_words(words, tab, HAS_TS)
    return wptr, levels, rows


HAS_TS = 0


def pick_ts(words, tab):
    """1, если за заголовками идёт метка времени (6.2), иначе 0 (4.1).

    Число записей не годится как критерий: при неверном сдвиге мусорные
    слова тоже изредка попадают в строки. Надёжнее сама метка: в 6.2 слово
    за заголовком растёт от записи к записи (кольцо даёт один откат)."""
    ts = [words[r[0] + 1] for r in parse_words(words, tab, 1)
          if r[0] + 1 < len(words)]
    if len(ts) < 8:
        return 0
    up = sum(1 for a, b in zip(ts, ts[1:]) if 0 <= b - a < 0x1000000)
    return 1 if up > 0.8 * (len(ts) - 1) else 0


def find_wrap(rows):
    """Кольцо циклическое: точка записи там, где TSF в записях резко падает.
    Всё, что ПЕРЕД ней, — самое свежее."""
    # только записи вида "... curr tsf 0x%08x %08x" — там TSF идёт последним
    # аргументом. Брать любые строки с 'tsf' нельзя: в [PHY_LOG] он первый, и
    # смесь двух разных полей ломает монотонность.
    ts = [(i, a[-1]) for i, m, l, t, a in rows if 'curr tsf' in t and len(a) >= 2]
    for k in range(1, len(ts)):
        if ts[k][1] < ts[k - 1][1] * 0.9:
            return ts[k][0]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dump', nargs='?', help='blob_fw_peri (или blob_fw_data) с устройства')
    ap.add_argument('--strings', '-s', help='таблица строк (запись 101 образа)')
    ap.add_argument('--addr', '-a', help='адрес кольца из RGF_USER_USAGE_1, напр. 0x843900')
    ap.add_argument('--region', default='fw_peri', choices=sorted(BLOBS))
    ap.add_argument('-n', type=int, default=2048, help='сколько слов кольца разбирать')
    ap.add_argument('--tail', type=int, default=0, help='показать только последние N записей')
    ap.add_argument('--extract-strings', metavar='FW.fw')
    ap.add_argument('-o', '--outdir', default='.')
    a = ap.parse_args()

    if a.extract_strings:
        sys.exit(0 if extract_strings(a.extract_strings, a.outdir) else 1)
    if not (a.dump and a.strings and a.addr):
        ap.error('нужны dump, --strings и --addr')

    blob = open(a.dump, 'rb').read()
    tab = open(a.strings, 'rb').read()
    base = BLOBS[a.region][0]
    if a.region == 'uc_data':
        wptr, levels, rows = decode_ucode(blob, int(a.addr, 16), tab, base)
    else:
        wptr, levels, rows = decode(blob, base, int(a.addr, 16), tab, a.n)
    print('# кольцо @ %s  write_ptr=0x%x  уровни=%s  записей=%d'
          % (a.addr, wptr, ' '.join('%08x' % x for x in levels), len(rows)))
    if not any(levels):
        print('# уровни нулевые -> прошивка логирование не включила '
              '(echo 7 > /sys/module/wil6210/parameters/fw_log_level + сброс FW)')
    wrap = None if a.region == 'uc_data' else find_wrap(rows)
    if wrap is not None:
        print('# точка записи кольца: слово %d; ниже — последние записи перед ней' % wrap)
        rows = [r for r in rows if r[0] < wrap]
    if a.tail:
        rows = rows[-a.tail:]
    mods = UC_MODULES if a.region == 'uc_data' else MODULES
    for _, module, level, txt, args in rows:
        # в формате 6.2 биты 18..25 заголовка — байт отметки времени, а не
        # модуль/уровень (см. комментарий у MODULES)
        print('%-11s %-4s %s' % ('-' if HAS_TS else mods[module], '-' if HAS_TS else LEVELS[level],
                                 fmt_args(txt, args, tab)))


if __name__ == '__main__':
    main()
