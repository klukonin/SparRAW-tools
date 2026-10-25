#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RF sector tables of a wil6210 (Sparrow) board file <-> XML.

A Sparrow .brd carries the RF sector tables as blocks inside its data record:

    <key> <key> <hdr> <word> <n words of data>      n = (hdr & 0xfffff) >> 8

    key 0xc00c900d  TX sectors
    key 0xc00c900e  RX sectors

Every sector is six dwords, in this order in the file:

    psh_hi, psh_lo, etype0, etype1, dtype_swch_off, etype2

(WMI_GET/SET_RF_SECTOR_PARAMS carry etype2 before dtype_swch_off.)
Phase: 2 bits per element, interleaved -- elements 0..15 in psh_hi, 16..31 in
psh_lo.  This differs from Talyn, where the phase is split into a psh90 and a
psh180 bit-plane.  EType: a 3-bit edge amplifier gain index per element, bit k
of it in etype<k>, element i at bit i.

The XML uses the tag names of the vendor sector files (Phases, ETypes), one
value per element.  With --array the sector also gets the azimuth/elevation of
its main lobe in the array frame (pitch, layout and feed phases from a JSON file).

    wil_sectors.py brd2xml FILE.brd [-o OUT.xml] [--array A.json --channel N]
    wil_sectors.py xml2brd BASE.brd IN.xml -o OUT.brd
"""

import argparse
import math
import struct
import sys
import xml.etree.ElementTree as ET

import wil_brd

KEYS = {0xc00c900d: 'tx', 0xc00c900e: 'rx'}
N_EL = 32
CH_GHZ = {1: 58.32, 2: 60.48, 3: 62.64, 4: 64.80}


def find_blocks(blob):
    """Yield (kind, key, offset_of_key, hdr, word, data_offset, n_sectors)."""
    for key, kind in KEYS.items():
        pat = struct.pack('<II', key, key)
        off = blob.find(pat)
        while off >= 0:
            hdr, word = struct.unpack_from('<II', blob, off + 8)
            n_words = (hdr & 0xfffff) >> 8
            if n_words % 6:
                raise wil_brd.BadImage('%s block at 0x%x: %d words, not a multiple of 6'
                                       % (kind, off, n_words))
            yield kind, key, off, hdr, word, off + 16, n_words // 6
            off = blob.find(pat, off + 16 + 4 * n_words)


def decode_sector(w):
    psh_hi, psh_lo, e0, e1, dtype, e2 = w
    phases = [(psh_hi >> (2 * i)) & 3 for i in range(16)] + \
             [(psh_lo >> (2 * i)) & 3 for i in range(16)]
    etypes = [((e0 >> i) & 1) | (((e1 >> i) & 1) << 1) | (((e2 >> i) & 1) << 2)
              for i in range(N_EL)]
    return phases, etypes, dtype


def encode_sector(phases, etypes, dtype):
    hi = lo = e0 = e1 = e2 = 0
    for i in range(N_EL):
        if i < 16:
            hi |= (phases[i] & 3) << (2 * i)
        else:
            lo |= (phases[i] & 3) << (2 * (i - 16))
        e0 |= (etypes[i] & 1) << i
        e1 |= ((etypes[i] >> 1) & 1) << i
        e2 |= ((etypes[i] >> 2) & 1) << i
    return [hi, lo, e0, e1, dtype, e2]


def main_lobe(arr, kd, phases, etypes):
    """Peak of the array factor over the visible hemisphere -> (az, el) in degrees.

    az is the angle in the array x-z plane, el in the y-z plane (array frame,
    not calibrated against the housing).  Elements with etype 0 still count:
    the gain index scales amplitude, it does not switch the element off.
    """
    pos, beta = arr['pos'], arr['beta']
    z = [complex(math.cos(math.pi / 2 * p - b), math.sin(math.pi / 2 * p - b))
         for p, b in zip(phases, beta)]
    best = (-1.0, 0.0, 0.0)
    n = 81
    for r in range(n):
        sy = -1 + 2 * r / (n - 1)
        for q in range(n):
            sx = -1 + 2 * q / (n - 1)
            if sx * sx + sy * sy > 1:
                continue
            acc = 0j
            for (x, y), zi in zip(pos, z):
                t = kd * (sx * x + sy * y)
                acc += complex(math.cos(t), math.sin(t)) * zi.conjugate()
            g = abs(acc)
            if g > best[0]:
                best = (g, sx, sy)
    _, sx, sy = best
    return math.degrees(math.asin(sx)), math.degrees(math.asin(sy))


def cmd_brd2xml(a):
    blob, hdr, _ = wil_brd.load(a.brd)
    arr = kd = None
    if a.array:
        import json
        arr = json.load(open(a.array))
        kd = 2 * math.pi * arr['pitch_mm'] / (299.792458 / CH_GHZ[a.channel])
    root = ET.Element('sparrow_sectors', source=a.brd, crc='0x%08x' % hdr['crc'])
    if arr:
        root.set('array', a.array)
        root.set('channel', str(a.channel))
    for kind, key, off, bhdr, word, data, n in find_blocks(blob):
        blk = ET.SubElement(root, kind, key='0x%08x' % key, offset='0x%x' % off,
                            hdr='0x%08x' % bhdr, word='0x%08x' % word)
        for s in range(n):
            w = struct.unpack_from('<6I', blob, data + 24 * s)
            # file order -> logical order (etype2 before dtype)
            phases, etypes, dtype = decode_sector((w[0], w[1], w[2], w[3], w[4], w[5]))
            sec = ET.SubElement(blk, 'sector', Num=str(s))
            ET.SubElement(sec, 'Phases').text = ' '.join(map(str, phases))
            ET.SubElement(sec, 'ETypes').text = ' '.join(map(str, etypes))
            ET.SubElement(sec, 'dtype_swch_off').text = '0x%08x' % dtype
            if arr and any(e for e in etypes):
                az, el = main_lobe(arr, kd, phases, etypes)
                ET.SubElement(sec, 'azimuth').text = '%.1f' % az
                ET.SubElement(sec, 'elevation').text = '%.1f' % el
    ET.indent(root)
    out = ET.tostring(root, encoding='unicode') + '\n'
    if a.output:
        open(a.output, 'w').write(out)
    else:
        sys.stdout.write(out)


def cmd_xml2brd(a):
    blob, hdr, _ = wil_brd.load(a.base)
    blob = bytearray(blob)
    root = ET.parse(a.xml).getroot()
    blocks = {kind: (data, n) for kind, _, _, _, _, data, n in find_blocks(blob)}
    changed = 0
    for blk in root:
        if blk.tag not in blocks:
            sys.exit('%s: no %s sector block in %s' % (a.xml, blk.tag, a.base))
        data, n = blocks[blk.tag]
        for sec in blk.findall('sector'):
            s = int(sec.get('Num'))
            if s >= n:
                sys.exit('%s sector %d: block holds only %d sectors' % (blk.tag, s, n))
            phases = [int(v) for v in sec.findtext('Phases').split()]
            etypes = [int(v) for v in sec.findtext('ETypes').split()]
            if len(phases) != N_EL or len(etypes) != N_EL:
                sys.exit('%s sector %d: need %d Phases and ETypes' % (blk.tag, s, N_EL))
            if any(not 0 <= p <= 3 for p in phases) or any(not 0 <= e <= 7 for e in etypes):
                sys.exit('%s sector %d: Phases are 0..3, ETypes 0..7' % (blk.tag, s))
            dtype = int(sec.findtext('dtype_swch_off'), 0)
            new = encode_sector(phases, etypes, dtype)
            off = data + 24 * s
            if list(struct.unpack_from('<6I', blob, off)) != new:
                changed += 1
            struct.pack_into('<6I', blob, off, *new)
    struct.pack_into('<I', blob, wil_brd.HEAD.size + 8,
                     wil_brd.compute_crc(bytes(blob), hdr['data_len']))
    open(a.output, 'wb').write(blob)
    print('%s: %d sectors changed, crc 0x%08x' % (a.output, changed,
          struct.unpack_from('<I', blob, wil_brd.HEAD.size + 8)[0]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('brd2xml', help='sector tables of a .brd -> XML')
    p.add_argument('brd')
    p.add_argument('-o', '--output')
    p.add_argument('--array', help='array JSON: pos, beta, pitch_mm (adds azimuth/elevation)')
    p.add_argument('--channel', type=int, default=2, choices=sorted(CH_GHZ))
    p.set_defaults(fn=cmd_brd2xml)
    p = sub.add_parser('xml2brd', help='write sectors from XML into a base .brd')
    p.add_argument('base')
    p.add_argument('xml')
    p.add_argument('-o', '--output', required=True)
    p.set_defaults(fn=cmd_xml2brd)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
