#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Снятие кольца команд MAC (uCode CORE WRITE) через debugfs blob_uc_data.

Микрокод дублирует каждую отправку в MAC в кольцевой журнал: идиома
    mov r32,rX ; st.ab rX,[r25,0x4] ; bclr r25,r25,0xa
даёт кольцо 1024 Б = 256 слов по линкерному адресу 0x800000 ucode-данных,
что для хоста -- начало blob_uc_data (host 0x940000, см. sparrow_fw_mapping).

Слово: биты 31:24 -- код команды, 23:0 -- параметр.  Бит 31 в Sparrow
означает «продублировать событием PMC» и не входит в код.

Указателя записи (r25) в памяти нет, поэтому голова кольца ищется диффом
двух снимков: изменившиеся слова лежат в [head_prev, head_now).  Если за
интервал кольцо успело обернуться целиком, порядок восстановить нельзя --
инструмент об этом говорит прямо и не выдумывает последовательность.

Использование:
    wil_mac_ring.py --dump              # один снимок: частоты кодов
    wil_mac_ring.py --watch 0.05        # поток команд в порядке отправки
    wil_mac_ring.py --watch 0.05 -n 200 -o trace.txt
    wil_mac_ring.py --rate              # замер оборота кольца
"""
import argparse, collections, os, struct, sys, time

RING_WORDS = 256

# Что известно про коды на сегодня.  Пусто = не расшифровано.
# Источники: реверс 6.2 (ref/), пак Talyn (ref/SXD-CORE-WRITE.md).
CODES = {
    0x00: 'mark',            # метка трассировки: параметр = идентификатор точки
    0x01: 'mode_switch',     # mac_mode__switch_sequence, bi_mode_init_substep
    0x1d: 'lr_select',       # выбрать селектор локального чтения (MSXD_LR_RGF)
    0x27: 'event_mask',      # маска движка событий
    0x30: 'beacon_delay',    # задержка маяка
    0x3a: 'rf_chain',        # mac__set_rf_chain_state
    0x3b: 'rf_chain',
    0x3c: 'rf_chain',
    0x47: 'pmc_udef',        # PMC User Defined Command Register
    0x4d: 'lr_read_r55',     # чтение группы R55 в r55; 0=SIFS_CNT 5=TSF_LOW a=GP_CLK2
    0x4f: 'gp_timer0',
    0x50: 'gp_timer1',
    0x51: 'gp_timer2',
}


def read_ring(path):
    with open(path, 'rb') as f:
        b = f.read(RING_WORDS * 4)
    if len(b) < RING_WORDS * 4:
        sys.exit('прочитано %d Б вместо %d -- это blob_uc_data?'
                 % (len(b), RING_WORDS * 4))
    return list(struct.unpack('<%dI' % RING_WORDS, b))


def fmt(w):
    code, par = w >> 24, w & 0xffffff
    pmc = ' PMC' if code & 0x80 else ''
    code &= 0x7f
    nm = CODES.get(code, '')
    return '0x%02x %-14s 0x%06x%s' % (code, nm, par, pmc)


def window(a, b):
    """Кольцевое окно изменившихся слов: (начало, длина, надёжно) или None.

    ВАЖНО об ограничениях (проверено на реальных трассах):
    * если микрокод повторил ТО ЖЕ слово, дифф его не видит вовсе — в
      трассе маячащей AP 1619 переходов из 1799 дают «без изменений», а
      в снимке бывает всего ОДНО различное значение на 256 слов.  Значит
      частоты по этим данным — нижняя граница, а не измерение;
    * внутри найденного окна часть позиций может совпадать (7…11 % на
      реальных данных) — это старые слова, и командами их считать нельзя;
    * прежняя защита «обернулось целиком» требовала, чтобы отличались
      ВСЕ 256 слов, и не срабатывала никогда: словарь значений узкий.
      Теперь признаком служит либо большая доля различий, либо разрыв
      изменений на несколько кольцевых кусков.
    """
    diff = [i for i in range(RING_WORDS) if a[i] != b[i]]
    if not diff:
        return None
    # Признак переполнения — не «много кусков» (при узком словаре значений
    # повторы внутри окна рвут его на части, и это НОРМА: порог pieces>2
    # браковал до 91 % законных переходов), а «окно занимает почти всё
    # кольцо», то есть между снимками записано ~256 слов и порядок потерян.
    if len(diff) == RING_WORDS:
        return (0, RING_WORDS, False)
    # ищем самый длинный непрерывный ряд СОВПАДЕНИЙ -- за ним начинается окно
    best, cur, start = 0, 0, 0
    s0 = None
    for k in range(RING_WORDS * 2):
        i = k % RING_WORDS
        if a[i] == b[i]:
            if cur == 0:
                s0 = i
            cur += 1
            if cur > best:
                best, start = cur, s0
        else:
            cur = 0
        if k >= RING_WORDS and cur == 0:
            break
    head = (start + best) % RING_WORDS
    n = RING_WORDS - best
    if n > RING_WORDS - 16:          # почти всё кольцо перезаписано
        return (0, RING_WORDS, False)
    return (head, n, True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--debugfs', default='/sys/kernel/debug/ieee80211/phy0/wil6210')
    ap.add_argument('--blob', default=None, help='путь к blob_uc_data напрямую')
    ap.add_argument('--dump', action='store_true')
    ap.add_argument('--watch', type=float, metavar='СЕК')
    ap.add_argument('--rate', action='store_true')
    ap.add_argument('-n', '--passes', type=int, default=0, help='0 = без предела')
    ap.add_argument('-o', '--out')
    a = ap.parse_args()

    path = a.blob or os.path.join(a.debugfs, 'blob_uc_data')
    if not os.path.exists(path):
        sys.exit('нет %s' % path)
    out = open(a.out, 'w') if a.out else sys.stdout

    if a.dump:
        r = read_ring(path)
        c = collections.Counter((w >> 24) & 0x7f for w in r)
        print('# снимок кольца, 256 слов; порядок неизвестен (нет указателя)',
              file=out)
        for code, n in sorted(c.items()):
            print('0x%02x %-14s %3d' % (code, CODES.get(code, ''), n), file=out)
        return

    if a.rate:
        prev = read_ring(path)
        t0 = time.time()
        for _ in range(20):
            time.sleep(0.02)
            cur = read_ring(path)
            w = window(prev, cur)
            dt = time.time() - t0
            if w:
                full = '' if w[2] else ' ПОРЯДОК НЕ ВОССТАНОВИМ'
                print('%.3f с: новых слов %3d%s' % (dt, w[1], full), file=out)
            prev, t0 = cur, time.time()
        return

    if a.watch is None:
        sys.exit('нужен --dump, --watch или --rate')

    prev = read_ring(path)
    seen, lost, quiet, k = 0, 0, 0, 0
    try:
        while not a.passes or k < a.passes:
            time.sleep(a.watch)
            cur = read_ring(path)
            k += 1
            w = window(prev, cur)
            if not w:
                quiet += 1
                continue
            head, n, ok = w
            if not ok:
                lost += 1
                print('# ... кольцо переполнено, порядок потерян', file=out)
            else:
                for j in range(n):
                    i = (head + j) % RING_WORDS
                    if prev[i] == cur[i]:
                        continue        # старое слово, не команда
                    print('%s' % fmt(cur[i]), file=out)
                    seen += 1
            prev = cur
            out.flush()
    except KeyboardInterrupt:
        pass
    print('# снято команд: %d, срывов (переполнение): %d, тихих переходов: %d'
          % (seen, lost, quiet), file=out)
    uniq = len(set(prev))
    print('# различных значений в последнем снимке: %d из %d%s'
          % (uniq, RING_WORDS,
             '  <- кольцо однородно, повторы невидимы' if uniq < 8 else ''),
          file=out)
    print('# ВНИМАНИЕ: повторы одного и того же слова диффом не видны, '
          'поэтому это НИЖНЯЯ граница числа команд', file=out)


if __name__ == '__main__':
    main()
