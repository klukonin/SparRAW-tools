#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Декодер ucode-лога wil6210 через debugfs mem_addr/memread.

Механизм (вскрыт реверсом 2026-09-20):
  * прошивка публикует адрес своего лог-кольца в RGF_USER_USAGE_2 = 0x880008
    (для fw-лога — RGF_USER_USAGE_1 = 0x880004). Драйвер обнуляет их ПЕРЕД
    стартом прошивки (wil_pre_fw_config -> wil_clear_fw_log_addr), поэтому
    ненулевое значение после загрузки = прошивка лог опубликовала.
  * формат записи кольца: 32-битное слово  (hdr<<16) | offset_строки,
    где offset — смещение в ucode-таблице строк (record type=100 образа),
    а в hdr биты [3:2] старшего байта = число аргументов (0..3).
    Аргументы кладутся в кольцо ПЕРЕД словом-заголовком.

Использование:
  wil_ucode_log.py --debugfs /sys/kernel/debug/ieee80211/phy0/wil6210 \
                   --strings tools/ucode_strings.json --version 6.2.0.1000 [--watch]
  wil_ucode_log.py --probe       # только показать адреса лог-буферов
"""
import argparse, json, os, sys, time

def rd(dbg, addr):
    try:
        with open(os.path.join(dbg,'mem_addr'),'w') as f: f.write(hex(addr))
        with open(os.path.join(dbg,'memread')) as f: t=f.read()
    except OSError as e:
        return None
    if '=' not in t: return None
    v=t.split('=')[1].strip()
    if 'INVALID' in v: return None
    try: return int(v,16)
    except ValueError: return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--debugfs','-d')
    ap.add_argument('--strings','-s', default='tools/ucode_strings.json')
    ap.add_argument('--version','-v', default='6.2.0.1000')
    ap.add_argument('--entries','-n', type=int, default=256)
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--watch','-w', action='store_true')
    a=ap.parse_args()

    dbg=a.debugfs
    if not dbg:
        for root,dirs,_ in os.walk('/sys/kernel/debug'):
            if os.path.basename(root)=='wil6210': dbg=root; break
    if not dbg or not os.path.exists(os.path.join(dbg,'mem_addr')):
        sys.exit('не найден debugfs wil6210 (укажи --debugfs)')

    fw_log = rd(dbg, 0x880004)
    uc_log = rd(dbg, 0x880008)
    print('debugfs      : %s'%dbg)
    print('RGF_USER_USAGE_1 (fw log addr)    = %s'%(hex(fw_log) if fw_log is not None else '?'))
    print('RGF_USER_USAGE_2 (ucode log addr) = %s'%(hex(uc_log) if uc_log is not None else '?'))
    if a.probe: return
    if not uc_log:
        print('\nucode-лог не опубликован (0) — прошивка логирование не включила.')
        print('Попробуй fw-лог (0x880004) либо инструментованную прошивку 4.1.0.1000.')
        return

    tabs=json.load(open(a.strings))
    if a.version not in tabs:
        sys.exit('нет таблицы строк для %s (есть: %s)'%(a.version, ', '.join(tabs)))
    strings={int(k):v for k,v in tabs[a.version]['strings'].items()}

    def dump():
        words=[]
        for i in range(a.entries):
            w=rd(dbg, uc_log + i*4)
            words.append(w if w is not None else 0)
        out=[]
        for i,w in enumerate(words):
            off=w & 0xffff; hdr=(w>>16)&0xffff
            if off in strings and 0x8000 <= hdr <= 0xffff:
                nargs=((hdr>>8)>>2)&3
                args=[words[i-1-k] for k in range(nargs)] if i>=nargs else []
                txt=strings[off]
                try: txt=txt % tuple(args) if nargs and '%' in txt else txt
                except Exception: txt='%s  args=%s'%(txt,[hex(x) for x in args])
                out.append('[%3d] %s'%(i,txt))
        return out

    while True:
        lines=dump()
        print('\n'.join(lines) if lines else '(в кольце нет распознанных записей)')
        if not a.watch: break
        time.sleep(1); print('-'*60)

if __name__=='__main__': main()
