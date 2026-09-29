#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Resolve real state/event/SM names for the 15 Sparrow state machines.

Method (definitive): each SM descriptor in the wil6210 firmware carries, beyond the
transition table, two arrays `state_names[ns]` and `event_names[ne]` of pointers into
the firmware's log-strings segment (record type 101, mapped at VA 0x01000000). The
UBNT 6.2.0.225 image is stripped (name arrays point to empty strings) but the MikroTik
6.2.0.1000 image keeps them. Since the two images share the SAME transition graphs
(verified: 14/15 byte-identical next-state matrices, SM09 differs by 1 cell), we:

  1. decode every SM descriptor in both images -> (ne, ns, next-state grid, name ptrs)
  2. for each UBNT SM (desc addr from ubnt-sparrow/sm_catalog.json) grid-match the
     MikroTik descriptor with the same next-state graph
  3. resolve that MikroTik descriptor's state/event name arrays via base 0x01000000
  4. name the SM itself by matching its resolved event list to the pool's `*_SM` blocks

Descriptor layout: {u8 nevents, u8 nstates, u16 pad, u32 trans, u32 state_names,
u32 event_names, ...}; all pointers linker-space (+0x100000 -> AHB for fw_data).
Transition table: ns*ne records of 5 bytes {u32 action_off, u8 next_state},
index = state + event*nstates.
"""
import struct, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UBNT_FW = os.environ.get('UBNT_FW', '')  # образ UBNT Sparrow+ (в репозитории нет)
MTIK_FW = os.environ.get('MTIK_FW', os.path.join(ROOT, '..', 'SparRAW-firmware', 'blobs', 'stock', 'wil6210_6.2.0.1000_stock_raw.fw'))
CATALOG = os.environ.get('SM_CATALOG', os.path.join(HERE, 'sm_catalog.json'))
STRSEG_BASE = 0x01000000            # record-101 log-strings segment VA base


def load_fw(path):
    """Parse wil6210 container -> {load_addr: payload} for data records, plus 'pool'."""
    d = open(path, 'rb').read(); off = 0; mem = {}
    while off + 8 <= len(d):
        t, fl, sz = struct.unpack_from('<HHI', d, off); body = d[off + 8:off + 8 + sz]
        if t == 2 and sz >= 4:
            mem[struct.unpack_from('<I', body, 0)[0]] = body[4:]
        elif t == 101:
            mem['pool'] = body
        off += 8 + sz
    return mem


def rd(mem, va, n):
    for b, p in mem.items():
        if isinstance(b, int) and b <= va < b + len(p):
            return p[va - b:va - b + n]
    return None


def lk(v):
    return v + 0x100000 if 0x800000 <= v < 0x900000 else v


def resolve_str(pool, va):
    o = va - STRSEG_BASE
    if 0 <= o < len(pool):
        e = pool.find(b'\x00', o)
        return pool[o:e].decode('latin1')
    return None


def decode_desc(mem, dva, pool=None):
    """Return (ne, ns, grid, states, events). grid is next-state tuple-of-tuples."""
    d = rd(mem, dva, 16)
    ne, ns = d[0], d[1]
    trans = lk(struct.unpack_from('<I', d, 4)[0])
    t = rd(mem, trans, ns * ne * 5)
    grid = tuple(tuple(t[(s + e * ns) * 5 + 4] for e in range(ne)) for s in range(ns))
    states = events = None
    if pool is not None:
        sn = lk(struct.unpack_from('<I', d, 8)[0]); en = lk(struct.unpack_from('<I', d, 12)[0])
        snb = rd(mem, sn, ns * 4); enb = rd(mem, en, ne * 4)
        if snb:
            states = [resolve_str(pool, x) for x in struct.unpack('<%dI' % ns, snb)]
        if enb:
            events = [resolve_str(pool, x) for x in struct.unpack('<%dI' % ne, enb)]
    return ne, ns, grid, states, events


def scan_descs(mem):
    """Find every valid SM descriptor -> {addr: (ne, ns, grid)}."""
    out = {}
    for base, pay in mem.items():
        if not isinstance(base, int):
            continue
        for i in range(len(pay) - 16):
            ne, ns = pay[i], pay[i + 1]
            if not (2 <= ne <= 14 and 2 <= ns <= 8) or pay[i + 2] or pay[i + 3]:
                continue
            trans = lk(struct.unpack_from('<I', pay, i + 4)[0]); t = rd(mem, trans, ns * ne * 5)
            if not t or len(t) < ns * ne * 5:
                continue
            g = [t[k * 5 + 4] for k in range(ns * ne)]
            ap = [struct.unpack_from('<I', t, k * 5)[0] for k in range(ns * ne)]
            if any(x >= ns for x in g) or any(not (x == 0 or x < 0x40000) for x in ap) or not any(g):
                continue
            out[base + i] = (ne, ns, tuple(tuple(g[s + e * ns] for e in range(ne)) for s in range(ns)))
    return out


def pool_sm_tokens(pool):
    """[(offset, SM_NAME)] for every `*_SM` token in pool order (block delimiters)."""
    return [(m.start(), m.group()[:-1].decode('latin1'))
            for m in re.finditer(rb'[A-Z][A-Z0-9_]{2,}_SM\x00', pool)]


def desc_name_span(mem, dva, pool):
    """Pool-offset span [lo, hi] covered by this descriptor's state+event name strings."""
    d = rd(mem, dva, 16); ne, ns = d[0], d[1]
    sn = lk(struct.unpack_from('<I', d, 8)[0]); en = lk(struct.unpack_from('<I', d, 12)[0])
    offs = []
    for ptr, cnt in ((sn, ns), (en, ne)):
        b = rd(mem, ptr, cnt * 4)
        if b:
            offs += [p - STRSEG_BASE for p in struct.unpack('<%dI' % cnt, b)
                     if 0 <= p - STRSEG_BASE < len(pool)]
    return (min(offs), max(offs)) if offs else None


def short_state(s, i):
    if not s:
        return 'S%d' % i
    return s.replace('STATE_', '').replace('WAIT_FOR_', 'WF_').replace('_STATE', '')


def short_event(e, i):
    if not e:
        return 'E%d' % i
    return e.replace('EVT_', '').replace('RM_', '')


def emit_named_matrices(ub, ubd, results):
    """Print markdown: each of the 15 matrices with real state/event names.
    Cells = next-state index; a per-SM legend maps E#/S# -> name. Transition data
    is the canonical UBNT grid (identical to MikroTik save SM09's 1 cell)."""
    print('# Именованные матрицы 17 автоматов Sparrow (state×event → next_state)\n')
    print('Имена состояний/событий — из name-таблиц дескрипторов MikroTik 6.2.0.1000,')
    print('переходы — из UBNT 6.2.0.225 (графы идентичны, кроме 1 ячейки SM09).')
    print('Ячейка = индекс следующего состояния. `.` = переход в себя (no-op).\n')
    for sm in sorted(results):
        r = results[sm]
        if not r['mtik'] or r['ubnt'] == '-':
            continue
        addr = int(r['ubnt'], 16)
        ne, ns, g = ubd[addr]
        st = r['states'] or [None] * ns
        ev = r['events'] or [None] * ne
        print('### %s = %s  (%d×%d, MTik %s, diff %s)' % (sm, r['name'], ns, ne, r['mtik'], r['diff']))
        print('states: ' + ', '.join('S%d=%s' % (i, short_state(st[i], i)) for i in range(ns)))
        print('events: ' + ', '.join('E%d=%s' % (i, short_event(ev[i], i)) for i in range(ne)))
        print('```')
        print('       ' + ' '.join('E%-2d' % e for e in range(ne)))
        for s in range(ns):
            cells = ' '.join((' . ' if g[s][e] == s else '%3d' % g[s][e]) for e in range(ne))
            print('  S%-2d: %s' % (s, cells))
        print('```\n')


def main():
    ub = load_fw(UBNT_FW); mt = load_fw(MTIK_FW); pool = mt['pool']
    cat = json.load(open(CATALOG))
    ubd = scan_descs(ub); mtd = scan_descs(mt)
    sm_tokens = pool_sm_tokens(pool)

    # our SM## -> UBNT descriptor addr, from SM-CATALOG / SM-ALL-MATRICES
    sm_addr = {'SM00': 0x901f0c, 'SM01': 0x90275c, 'SM02': 0x902c9c, 'SM03': 0x902b14,
               'SM04': 0x901e08, 'SM05': 0x902364, 'SM06': 0x902f48, 'SM07': 0x902cb0,
               'SM08': 0x90307c, 'SM09': 0x902b70, 'SM10': 0x902fe0, 'SM11': 0x902880,
               'SM12': 0x902528, 'SM13': 0x902dcc, 'SM14': 0x90295c,
               # found later by descriptor scan (UBNT has 17, not 15):
               'SM15': 0x90201c, 'SM16': 0x90270c}

    results = {}
    # pass 1: grid-match each SM -> MikroTik descriptor, resolve names + name-span
    for sm, addr in sm_addr.items():
        if addr not in ubd:
            continue
        ne, ns, g = ubd[addr]
        cand = [(ma, mg) for ma, (mne, mns, mg) in mtd.items() if mns == ns and mne == ne]
        if not cand:
            results[sm] = dict(dims='%dx%d' % (ns, ne), ubnt='0x%06x' % addr, mtik=None,
                               diff='-', name=None, states=None, events=None, span=None)
            continue
        ma, mg = min(cand, key=lambda c: sum(g[s][e] != c[1][s][e] for s in range(ns) for e in range(ne)))
        diff = sum(g[s][e] != mg[s][e] for s in range(ns) for e in range(ne))
        _, _, _, states, events = decode_desc(mt, ma, pool)
        results[sm] = dict(dims='%dx%d' % (ns, ne), ubnt='0x%06x' % addr, mtik='0x%06x' % ma,
                           diff='%d/%d' % (diff, ns * ne), name=None, states=states, events=events,
                           span=desc_name_span(mt, ma, pool))

    # pass 2: assign each pool `*_SM` token to the SM whose name-block ends nearest before it
    for off, nm in sm_tokens:
        owner = None; best_hi = -1
        for sm, r in results.items():
            if r['span'] and r['span'][1] <= off and r['span'][1] > best_hi:
                best_hi = r['span'][1]; owner = sm
        if owner and results[owner]['name'] is None:
            results[owner]['name'] = nm

    # documented corrections (adjacency edge cases; evidence in comments):
    #  SM12: events end at EVT_BA_SETUP_SM_ABORT_DONE (pool 0x20142) immediately
    #        followed by the BA_SM token (0x20159); states are the BA agreement
    #        lifecycle. Auto-adjacency slipped to BA_SETUP_SM via shared event strings.
    #  SM04: radio-calibration/correction sub-SM (IDLE/CHECK_CORRECTION_NEEDED/
    #        WAIT_FOR_RADIO_LOCK/CORRECTION); no dedicated *_SM token exists in the pool.
    #  SM01: name strings stripped even in MikroTik; role "STA sub-SM" per SM-CATALOG.
    #  SM15/SM16 were missing from the original 15-SM catalog entirely.
    OVERRIDE = {'SM12': 'BA_SM', 'SM04': 'CALIB_SM (correction; no pool token)',
                'SM01': '? (names stripped; STA sub-SM per SM-CATALOG)',
                'SM15': 'MLME_SM', 'SM16': 'BA_SETUP_SM'}
    for sm, nm in OVERRIDE.items():
        if sm in results:
            results[sm]['name'] = nm

    print('%-5s %-6s %-10s %-10s %-5s %-24s' % ('SM', 'dims', 'UBNT', 'MTik', 'diff', 'name'))
    for sm in sorted(results):
        r = results[sm]
        print('%-5s %-6s %-10s %-10s %-5s %-24s' % (
            sm, r['dims'], r['ubnt'], r['mtik'] or '-', r['diff'], r['name'] or '?'))

    if '--matrices' in sys.argv:
        emit_named_matrices(ub, ubd, results)
    if '--json' in sys.argv:
        print('\n' + json.dumps(results, indent=1))
    if '--full' in sys.argv:
        for sm in sorted(results):
            r = results[sm]
            print('\n## %s = %s  (%s, MTik desc %s, next-state diff %s)' % (sm, r['name'], r['dims'], r['mtik'], r['diff']))
            if r['states']:
                print('  states: ' + ', '.join('%d=%s' % (i, s) for i, s in enumerate(r['states'])))
            if r['events']:
                print('  events: ' + ', '.join('%d=%s' % (i, e) for i, e in enumerate(r['events'])))
    return results


if __name__ == '__main__':
    main()
