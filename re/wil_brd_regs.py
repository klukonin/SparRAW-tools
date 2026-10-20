#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Разбор секции RF-регистров board-файла wil6210 и патч по методу RouterOS.

Формат (вскрыт реверсом RouterOS nova/bin/wireless, FUN_0003f234):
  ... <key:u32> <key:u32> <hdr:u32> <0xdeadbeef> (<reg:u32> <val:u32>)*
  количество пар = (hdr & 0xfffff) >> 8, регистры всегда < 0x10000
"""
import struct, sys

KEY = 0xb000900d

def find_section(d, key=KEY):
    pat = struct.pack('<II', key, key)
    off = d.find(pat)
    if off < 0:
        return None
    hdr = struct.unpack_from('<I', d, off + 8)[0]
    n = (hdr & 0xfffff) >> 8
    return off, hdr, n, off + 16          # пары начинаются после key,key,hdr,deadbeef

def pairs(d):
    f = find_section(d)
    if not f: return []
    off, hdr, n, p = f
    out = []
    for i in range(n // 2):  # n — в словах, пара = 2 слова
        o = p + i * 8
        if o + 8 > len(d): break
        reg, val = struct.unpack_from('<II', d, o)
        if reg >= 0x10000: break
        out.append((o, reg, val))
    return out

def routeros_patches(tx=None, rx=None, rfregs=None):
    """Пары (reg,val), которые RouterOS дописывает в таблицу."""
    p = []
    if tx is not None:
        p.append((0x1c, tx | 0x8000  | (tx << 8) | (tx << 4)))
        p.append((0x5c, tx | 0x40000 | (tx << 4)))
    if rx is not None:
        for o in range(0x28, 0x40, 4):
            p.append((o,        rx | 0x8000  | (rx << 4)))
            p.append((o + 0x40, rx | 0x10000 | (rx << 4)))
    if rfregs:
        p.extend(rfregs)
    return p

def apply_patches(d, patches):
    d = bytearray(d)
    tbl = pairs(d)
    idx = {}
    for o, reg, val in tbl:
        idx.setdefault(reg, []).append((o, val))
    changed = []
    for reg, val in patches:
        for o, old in idx.get(reg, []):
            if old != val:
                struct.pack_into('<I', d, o + 4, val)
                changed.append((reg, old, val))
    return bytes(d), changed

if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    f = find_section(d)
    if not f:
        print("секция RF-регистров не найдена"); sys.exit(1)
    off, hdr, n, p = f
    print("секция 0x%08x: смещение 0x%x, hdr=0x%08x, пар=%d, данные с 0x%x"
          % (KEY, off, hdr, n, p))
    t = pairs(d)
    print("реально прочитано пар: %d" % len(t))
    tgt = {0x1c, 0x5c} | set(range(0x28, 0x40, 4)) | set(range(0x68, 0x80, 4))
    print("--- регистры, которые патчит RouterOS ---")
    for o, reg, val in t:
        if reg in tgt:
            print("  @0x%04x  reg 0x%04x = 0x%08x" % (o, reg, val))

# --- контрольная сумма контейнера (driver: wil_fw_verify) ---
# crc32_le(~0, ...) по первым data_len байтам с обнулённым полем crc, затем ~.
# Это обычный zlib.crc32. Микротиковские brd содержат ПРОТУХШУЮ crc
# (у всех одна и та же 0xeb5c4046) — их драйвер её не проверяет, mainline проверяет
# и отвергает файл с -EINVAL, из-за чего прошивка не грузится вовсе.
import zlib

def brd_crc(data):
    d = bytearray(data)
    dlen = struct.unpack_from('<I', d, 0x18)[0]
    struct.pack_into('<I', d, 0x10, 0)
    return zlib.crc32(bytes(d[:dlen])) & 0xffffffff

def brd_fix_crc(data):
    """Вернуть (data_с_правильной_crc, была, стала)."""
    old = struct.unpack_from('<I', data, 0x10)[0]
    new = brd_crc(data)
    d = bytearray(data)
    struct.pack_into('<I', d, 0x10, new)
    return bytes(d), old, new
