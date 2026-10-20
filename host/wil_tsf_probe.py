#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
r"""Прямая проверка рандомизированного биконинга через аппаратный TSF-компаратор.

МЕХАНИЗМ (реверс 2026-09-20, ucode FUN_00930c28 = set_tsf_event):
    0x886d30  целевой TSF, младшее слово   \  аппаратный компаратор:
    0x886d34  целевой TSF, старшее слово    >  ucode кладёт сюда "Next TSF"
    0x886d38  управление: 0xc0050=ВКЛ / 0xc0010=ВЫКЛ
    0x886eb8/0x886ebc  текущий TSF (low/high),  0x886eb4 статус
Все они в регионе `rgf` (0x880000..0x88a000), помеченном доступным в
sparrow_fw_mapping ⇒ читаются через debugfs mem_addr/memread БЕЗ патча драйвера.

ЧТО ЭТО ДАЁТ: рандомизатор вычисляет Next TSF = now + delay, где
delay = (((rand * 0xbd) >> 32) + 10) * 10 мкс  ⇒  ожидаемый диапазон ≈[100,1980] мкс.
Если delta скачет в этом диапазоне от интервала к интервалу — рандомизация РАБОТАЕТ.
Если delta постоянная — биконинг не рандомизирован (обычный режим).

Работает на ЛЮБОЙ версии прошивки (механизм есть в 4.1, 5.2 и 6.2).

Использование:
    ./wil_tsf_probe.py                 # 40 замеров
    ./wil_tsf_probe.py -n 200 -i 0.05
"""
import argparse, os, sys, time

R_TGT_LO, R_TGT_HI, R_CTL = 0x886d30, 0x886d34, 0x886d38
R_TSF_LO, R_TSF_HI, R_TSF_ST = 0x886eb8, 0x886ebc, 0x886eb4

def rd(dbg, addr):
    try:
        with open(os.path.join(dbg,'mem_addr'),'w') as f: f.write(hex(addr))
        with open(os.path.join(dbg,'memread')) as f: t=f.read()
    except OSError:
        return None
    if '=' not in t: return None
    v=t.split('=')[1].strip()
    if 'INVALID' in v: return None
    try: return int(v,16)
    except ValueError: return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--debugfs','-d')
    ap.add_argument('-n','--count',type=int,default=40)
    ap.add_argument('-i','--interval',type=float,default=0.1)
    a=ap.parse_args()
    dbg=a.debugfs
    if not dbg:
        for root,dirs,_ in os.walk('/sys/kernel/debug'):
            if os.path.basename(root)=='wil6210': dbg=root; break
    if not dbg or not os.path.exists(os.path.join(dbg,'mem_addr')):
        sys.exit('не найден debugfs wil6210 (укажи --debugfs)')

    ctl=rd(dbg,R_CTL)
    print('debugfs: %s'%dbg)
    print('TSF-event control (0x886d38) = %s  %s'%(
        hex(ctl) if ctl is not None else '?',
        {0xc0050:'ВКЛЮЧЕН',0xc0010:'выключен'}.get(ctl,'?')))
    print()
    print('  %-18s %-18s %10s'%('current TSF','next beacon TSF','delta, мкс'))
    seen=[]
    for _ in range(a.count):
        lo=rd(dbg,R_TSF_LO); hi=rd(dbg,R_TSF_HI)
        tl=rd(dbg,R_TGT_LO); th=rd(dbg,R_TGT_HI)
        if None in (lo,hi,tl,th):
            print('  чтение не удалось'); break
        cur=(hi<<32)|lo; tgt=(th<<32)|tl
        d=tgt-cur
        print('  0x%016x 0x%016x %10s'%(cur,tgt, d if -10**7<d<10**7 else '—'))
        if 0 < d < 10**7: seen.append(d)
        time.sleep(a.interval)
    if seen:
        lo_,hi_=min(seen),max(seen)
        uniq=len(set(seen))
        print('\nзамеров с валидной delta: %d, различных: %d, диапазон %d..%d мкс'%(len(seen),uniq,lo_,hi_))
        if uniq>3 and hi_-lo_>50:
            print('ВЕРДИКТ: задержка ВАРЬИРУЕТСЯ ⇒ рандомизация маяка работает.')
            print('         (ожидаемый диапазон по формуле ≈100..1980 мкс)')
        else:
            print('ВЕРДИКТ: задержка почти постоянна ⇒ рандомизации не видно.')
    else:
        print('\nвалидных замеров нет: TSF-событие не взведено или биконинг не запущен.')

if __name__=='__main__': main()
