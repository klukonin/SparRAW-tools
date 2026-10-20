#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Symbol maps for wil6210 / Talyn firmware and ucode.

The WIGIG.TLN release ships two symbol maps next to the images:

    globals/TALYN_M_B0/fw_image_globals.xml      455 globals, 42432 nodes
    globals/TALYN_M_B0/ucode_image_globals.xml   481 globals, 34376 nodes

Each <node> carries an address, a name, a type and a bit range:

    <node address="0xa202c4" name="error_level_enable" type="field"
          start="0" end="0" />

start/end are bit offsets counted from the node's own address, LSB first
(the images are little-endian), so a node covers bits
[address*8 + start .. address*8 + end].  A "field" is a bitfield leaf, a
"table" is anything that contains structure: a struct, a union, an array,
an enum or a scalar.  Two name shapes are special: "<7>" is array element 7
and "<286331153>HW_BOOT_DONE" is an enum constant with value 286331153
(such nodes have end = -1, i.e. zero width).

Addresses in both files are AHB (host-side) addresses -- the same space the
.fw container's data records are loaded into -- not linker addresses.  The
translation table is Talyn's, copied from the vendor's own host_manager_11ad
(access_layer_11ad/AddressTranslator.cpp), which in turn copies it from the
Linux driver.  Pointer values stored *inside* firmware data are linker
addresses, so both directions are provided.
"""

import argparse
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET

try:
    import wil_brd
except ImportError:                                  # running from elsewhere
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import wil_brd


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GLOBALS = os.path.join(HERE, '..', 'WIGIG_TLN_7.5_11ad_pack',
                               'globals', 'TALYN_M_B0')

FILES = {'fw': 'fw_image_globals.xml', 'ucode': 'ucode_image_globals.xml'}


class SymError(Exception):
    pass


# ------------------------------------------------------------------ regions
# Talyn linker <-> AHB map, verbatim from AddressTranslator.cpp
# (talyn_fw_mapping, "All translation tables are copied from the driver code").
# fields: linker_begin, linker_end (exclusive), ahb_begin, name, is_fw

TALYN_MB_REGIONS = [
    (0x000000, 0x0c0000, 0x900000, 'fw_code',      True),
    (0x800000, 0x820000, 0xa00000, 'fw_data',      True),
    (0x840000, 0x858000, 0xa20000, 'fw_peri',      True),
    (0x880000, 0x88a000, 0x880000, 'rgf',          True),
    (0x88a000, 0x88b000, 0x88a000, 'AGC_tbl',      True),
    (0x88b000, 0x88c000, 0x88b000, 'rgf_ext',      True),
    (0x88c000, 0x88c8d0, 0x88c000, 'mac_rgf_ext',  True),
    (0x88d000, 0x88e000, 0x88d000, 'ext_user_rgf', True),
    (0x890000, 0x894000, 0x890000, 'sec_pka',      True),
    (0x898000, 0x898c18, 0x898000, 'sec_kdf_rgf',  True),
    (0x89a000, 0x89a84c, 0x89a000, 'sec_main',     True),
    (0x8a0000, 0x8a1000, 0x8a0000, 'otp',          True),
    (0x8b0000, 0x8c0000, 0x8b0000, 'dma_ext_rgf',  True),
    (0x8c0000, 0x8c0210, 0x8c0000, 'dum_user_rgf', True),
    (0x8c2000, 0x8c2128, 0x8c2000, 'dma_ofu',      True),
    (0x8c3000, 0x8c4000, 0x8c3000, 'ucode_debug',  True),
    (0x900000, 0xa80000, 0x900000, 'upper',        True),
    # UCODE regions must stay after the FW ones, as in the driver: their
    # linker addresses collide with the FW ones and are only reachable by
    # AHB address.
    (0x000000, 0x040000, 0xa38000, 'uc_code',      False),
    (0x800000, 0x808000, 0xa78000, 'uc_data',      False),
]

# Talyn (non-MB).  The vendor's own host_manager_11ad carries only this one
# and calls it "the TALYN map", which is a trap: TALYN_M_B0 is Talyn-MB and
# has 768k of code RAM plus the sec_*, dum_user_rgf, dma_ofu and ucode_debug
# regions that this table does not know about.
TALYN_REGIONS = [
    (0x000000, 0x100000, 0x900000, 'fw_code',      True),
    (0x800000, 0x820000, 0xa00000, 'fw_data',      True),
    (0x840000, 0x858000, 0xa20000, 'fw_peri',      True),
    (0x880000, 0x88a000, 0x880000, 'rgf',          True),
    (0x88a000, 0x88b000, 0x88a000, 'AGC_tbl',      True),
    (0x88b000, 0x88c000, 0x88b000, 'rgf_ext',      True),
    (0x88c000, 0x88c540, 0x88c000, 'mac_rgf_ext',  True),
    (0x88d000, 0x88e000, 0x88d000, 'ext_user_rgf', True),
    (0x8a0000, 0x8a1000, 0x8a0000, 'otp',          True),
    (0x8b0000, 0x8c0000, 0x8b0000, 'dma_ext_rgf',  True),
    (0x900000, 0xa80000, 0x900000, 'upper',        True),
    (0x000000, 0x040000, 0xa38000, 'uc_code',      False),
    (0x800000, 0x808000, 0xa78000, 'uc_data',      False),
]

# Sparrow / Sparrow+ (the pre-Talyn 60 GHz radio, wil6210 FW 6.x). From the
# driver's sparrow_fw_mapping (wmi.c); mac_rgf_ext uses the D0 size, since
# "sparrow_plus" is Sparrow D0.
SPARROW_REGIONS = [
    (0x000000, 0x040000, 0x8c0000, 'fw_code',     True),
    (0x800000, 0x808000, 0x900000, 'fw_data',     True),
    (0x840000, 0x860000, 0x908000, 'fw_peri',     True),
    (0x880000, 0x88a000, 0x880000, 'rgf',         True),
    (0x88a000, 0x88b000, 0x88a000, 'AGC_tbl',     True),
    (0x88b000, 0x88c000, 0x88b000, 'rgf_ext',     True),
    (0x88c000, 0x88c500, 0x88c000, 'mac_rgf_ext', True),
    (0x8c0000, 0x949000, 0x8c0000, 'upper',       True),
    (0x000000, 0x020000, 0x920000, 'uc_code',     False),
    (0x800000, 0x804000, 0x940000, 'uc_data',     False),
]

CHIPS = {'talyn-mb': TALYN_MB_REGIONS, 'talyn': TALYN_REGIONS,
         'sparrow': SPARROW_REGIONS}
CHIP = 'talyn-mb'
REGIONS = CHIPS[CHIP]


def set_chip(name):
    """Pick the remapping table.  TALYN_M_B0 -- the chip both globals files
    describe -- is Talyn-MB."""
    global CHIP, REGIONS
    if name not in CHIPS:
        raise SymError('chip must be one of %s' % ', '.join(sorted(CHIPS)))
    CHIP, REGIONS = name, CHIPS[name]


def region_for_segment(addr):
    """Name a loadable segment's region. A segment starts exactly at a
    region's host base, so an exact base match wins over a merely containing
    region (fw_peri and uc_code overlap on Sparrow; the 0x920000 segment is
    uc_code, not the fw_peri that also spans it). 'upper' is the last resort.
    Returns (linker_addr, name, is_exec)."""
    exact = containing = None
    for lo, hi, ahb, name, is_fw in REGIONS:
        if name == 'upper':
            continue
        if ahb == addr:
            exact = (lo, name, name in ('fw_code', 'uc_code'))
        elif ahb <= addr < ahb + (hi - lo) and containing is None:
            containing = (lo + (addr - ahb), name,
                          name in ('fw_code', 'uc_code'))
    if exact:
        return exact
    if containing:
        return containing
    # fall back to 'upper' identity
    for lo, hi, ahb, name, is_fw in REGIONS:
        if name == 'upper' and ahb <= addr < ahb + (hi - lo):
            return (addr, name, True)
    return (None, '?', False)


def fw_code_base():
    """Host (AHB) base of the fw code region -- reset vector lives here.
    0x900000 on Talyn, 0x8c0000 on Sparrow."""
    for lo, hi, ahb, name, _is_fw in REGIONS:
        if name == 'fw_code':
            return ahb
    return REGIONS[0][2]


def linker_to_ahb(addr):
    """Linker address -> AHB address.  First match wins, as in the vendor's
    AddressTranslator::ToAhbAddress."""
    for lo, hi, ahb, name, _is_fw in REGIONS:
        if lo <= addr < hi:
            return ahb + (addr - lo), name
    return None, None


def ahb_to_linker(addr, image='fw'):
    """AHB address -> (linker address, region name).

    Ambiguous in principle: 'upper' maps 0x900000..0xa80000 onto itself and
    therefore covers fw_data, fw_peri and both ucode regions as well.  We
    prefer the region that belongs to the image being worked on and fall
    back to the identity mapping of 'upper'.
    """
    want_fw = image != 'ucode'
    fallback = None
    for lo, hi, ahb, name, is_fw in REGIONS:
        size = hi - lo
        if ahb <= addr < ahb + size:
            if name == 'upper':
                fallback = fallback or (addr, name)
                continue
            if is_fw != want_fw:
                fallback = fallback or (lo + (addr - ahb), name)
                continue
            return lo + (addr - ahb), name
    return fallback if fallback else (None, None)


def region_of(addr, image='fw'):
    return ahb_to_linker(addr, image)[1]


# ------------------------------------------------------------------- parsing

ENUM_RE = re.compile(r'^<(-?\d+)>(.+)$')
INDEX_RE = re.compile(r'^<(\d+)>$')


class Node(object):
    __slots__ = ('addr', 'name', 'kind', 'start', 'end', 'kids', 'parent',
                 'transparent', 'path')

    def __init__(self, el, parent):
        self.addr = int(el.get('address', '0x0'), 16)
        self.name = el.get('name')
        self.kind = el.get('type', 'root')
        self.start = int(el.get('start', 0))
        self.end = int(el.get('end', -1))
        self.parent = parent
        self.kids = []
        self.transparent = False
        self.path = None

    # -- geometry ---------------------------------------------------------
    @property
    def width(self):
        """Width in bits; 0 for enum constants (end == -1)."""
        return self.end - self.start + 1

    @property
    def bit0(self):
        """Absolute bit position of the first bit, LSB-first."""
        return self.addr * 8 + self.start

    @property
    def byte_addr(self):
        return self.bit0 // 8

    @property
    def size_bytes(self):
        if self.width <= 0:
            return 0
        return (self.bit0 % 8 + self.width + 7) // 8

    @property
    def is_bitfield(self):
        return self.width > 0 and (self.bit0 % 8 or self.width % 8)

    def access(self):
        """Dword access recipe for peek/poke: (dword_addr, shift, mask).

        None when the node does not fit a single 32-bit read (a struct, an
        array, a 64-bit counter); those are read as a byte range instead.
        """
        if not 0 < self.width <= 32:
            return None
        dw = self.byte_addr & ~3
        shift = self.bit0 - dw * 8
        if shift + self.width > 32:
            return None
        return dw, shift, ((1 << self.width) - 1) << shift

    # -- enums / arrays ---------------------------------------------------
    @property
    def enum_value(self):
        m = ENUM_RE.match(self.name)
        return int(m.group(1)) if m and self.width <= 0 else None

    @property
    def index(self):
        m = INDEX_RE.match(self.name)
        return int(m.group(1)) if m and self.width > 0 else None

    def eff_kids(self):
        """Children with the vendor's typedef/array wrappers expanded away."""
        out = []
        for k in self.kids:
            if k.transparent:
                out.extend(k.eff_kids())
            else:
                out.append(k)
        return out

    def signature(self):
        """Shape of the subtree, names of type wrappers excluded: two union
        views that describe the very same bits get the same signature."""
        kids = self.eff_kids()
        if not kids:
            return (self.addr, self.start, self.end, self.kind)
        return (self.addr, self.start, self.end,
                tuple(sorted((k.name, k.signature()) for k in kids)))

    def unique_kids(self):
        """Children with duplicate union views folded into the first one."""
        seen = {}
        out = []
        for k in self.eff_kids():
            sig = k.signature()
            if sig in seen:
                seen[sig].append(k.name)
                continue
            seen[sig] = []
            out.append(k)
        return out

    @property
    def label(self):
        idx = self.index
        return '[%d]' % idx if idx is not None else self.name

    def constants(self):
        """{value: name} if this node (or its collapsed chain) is an enum."""
        out = {}
        kids = self.eff_kids()
        if not kids:
            return {}
        for k in kids:
            v = k.enum_value
            if v is None:
                return {}
            out[v] = ENUM_RE.match(k.name).group(2)
        return out

    def __repr__(self):
        return '<Node %s @0x%06x [%d:%d]>' % (self.name, self.addr,
                                              self.end, self.start)


def _build(el, parent):
    node = Node(el, parent)
    node.kids = [_build(child, node) for child in el]
    return node


def _mark(node, depth=0):
    """Mark type wrappers as transparent and assign display paths.

    A node is transparent when it adds no information: it is the only child
    of its parent and covers exactly the same bits at the same address (a
    typedef/struct/enum type name), or it is the synthetic "Array" level
    whose children carry the indices.
    """
    for k in node.kids:
        same = (k.addr == node.addr and k.start == node.start
                and k.end == node.end)
        k.transparent = depth > 0 and ((len(node.kids) == 1 and same)
                                       or k.name == 'Array')
        idx = k.index
        if k.transparent:
            k.path = node.path
        elif idx is not None:
            k.path = '%s[%d]' % (node.path, idx)
        elif node.path:
            k.path = '%s.%s' % (node.path, k.name)
        else:
            k.path = k.name
        _mark(k, depth + 1)


def _bare(segment):
    """Strip a trailing array index: 'module_level_enable[3]' -> base name."""
    return re.sub(r'\[\d+\]$', '', segment)


class SymbolTable(object):
    def __init__(self, path, image):
        self.file = path
        self.image = image
        root = ET.parse(path).getroot()
        self.name = root.get('name')
        self.root = Node(root, None)
        self.root.path = ''
        self.root.kids = [_build(el, self.root) for el in root]
        _mark(self.root)
        self.globals = self.root.kids
        self.by_path = {}
        self.by_leaf = {}
        self.nodes = 0
        for n in self.walk():
            self.nodes += 1
            if n.enum_value is not None:
                continue
            self.by_path.setdefault(n.path, n)
            leaf = n.path.rsplit('.', 1)[-1]
            self.by_leaf.setdefault(_bare(leaf), []).append(n)

    def walk(self, node=None):
        node = self.root if node is None else node
        for k in node.kids:
            yield k
            for sub in self.walk(k):
                yield sub

    # -- lookup -----------------------------------------------------------
    def resolve(self, query):
        """Resolve a dotted path to a node.

        An exact path always wins.  Otherwise the query is matched as an
        ordered subsequence of path segments, so the vendor's typedef and
        union levels may be left out:

            g_log_table_header.module_level_enable[3].error_level_enable

        finds .../module_level_enable[3].tag_..._le.error_level_enable.
        Candidates that describe the very same bits (the same field reached
        through different union views) are not a conflict -- the shortest
        path is returned.
        """
        if query in self.by_path:
            return self.by_path[query]
        qs = query.split('.')
        last = qs[-1]
        cands = []
        for n in self.by_leaf.get(_bare(last), []):
            ps = n.path.split('.')
            if ps[-1] != last:
                continue
            i = 0
            for seg in ps[:-1]:
                if i < len(qs) - 1 and seg == qs[i]:
                    i += 1
            if i == len(qs) - 1:
                cands.append(n)
        if not cands:
            near = sorted(p for p in self.by_path if _bare(last) in p)[:8]
            raise SymError('no symbol %r%s' % (
                query, ('; near:\n  ' + '\n  '.join(near)) if near else ''))
        bits = {(n.addr, n.start, n.end) for n in cands}
        if len(bits) == 1:
            return min(cands, key=lambda n: (len(n.path), n.path))
        lines, seen = [], set()
        for n in sorted(cands, key=lambda n: (n.path, n.addr)):
            if n.path in seen:
                continue
            seen.add(n.path)
            lines.append('%-60s 0x%06x [%d:%d]' % (n.path, n.addr, n.end,
                                                  n.start))
        raise SymError('%r is ambiguous, %d distinct locations:\n  %s'
                       % (query, len(bits), '\n  '.join(lines[:12])))

    def at(self, addr, bit=None):
        """Every node covering an address (or one bit of it)."""
        lo = addr * 8 + (bit or 0)
        hi = lo + (1 if bit is not None else 8)
        out, seen = [], set()
        for n in self.walk():
            if n.width <= 0 or n.transparent or n.path in seen:
                continue
            if n.bit0 < hi and lo < n.bit0 + n.width:
                seen.add(n.path)
                out.append(n)
        out.sort(key=lambda n: (n.bit0, -n.width, n.path))
        return out

    def match(self, pattern, tops_only=True):
        import fnmatch
        pool = self.globals if tops_only else [
            n for n in self.walk() if n.enum_value is None]
        if not pattern:
            return list(pool)
        return [n for n in pool
                if fnmatch.fnmatch(n.name, pattern)
                or fnmatch.fnmatch(n.path, pattern)]


def load(image='fw', directory=None):
    directory = directory or DEFAULT_GLOBALS
    if image not in FILES:
        raise SymError('image must be fw or ucode, not %r' % image)
    path = os.path.join(directory, FILES[image])
    if not os.path.exists(path):
        raise SymError('no %s (pass --dir with the globals directory)' % path)
    return SymbolTable(path, image)


# ------------------------------------------------------------- memory source

class Memory(object):
    """Bytes of the AHB address space, from a .fw container or a raw dump."""

    def __init__(self, segments, source):
        self.segments = sorted(segments)      # [(addr, bytes)]
        self.source = source

    @classmethod
    def from_fw(cls, path):
        _blob, _hdr, records = wil_brd.load(path)
        segs = []
        for rec in records:
            if rec['type'] == 2 and len(rec['payload']) >= 4:
                addr = struct.unpack_from('<I', rec['payload'], 0)[0]
                segs.append((addr, rec['payload'][4:]))
        if not segs:
            raise SymError('%s has no data records' % path)
        return cls(segs, path)

    @classmethod
    def from_dump(cls, path, base):
        with open(path, 'rb') as fh:
            return cls([(base, fh.read())], path)

    def read(self, addr, size):
        for base, data in self.segments:
            if base <= addr and addr + size <= base + len(data):
                return data[addr - base:addr - base + size]
        return None

    def value(self, node):
        """Integer value of a node, or None when it is not in the image."""
        if node.width <= 0:
            return None
        raw = self.read(node.byte_addr, node.size_bytes)
        if raw is None:
            return None
        word = int.from_bytes(raw, 'little')
        return (word >> (node.bit0 % 8)) & ((1 << node.width) - 1)

    def describe(self):
        return ', '.join('0x%06x+%d' % (a, len(d)) for a, d in self.segments)


# ------------------------------------------------------------------ helpers

def fmt_bits(node):
    if node.width <= 0:
        return '   -   '
    if node.width == 1:
        return '   [%d]  ' % node.start
    return '[%d:%d]' % (node.end, node.start)


def fmt_addr(node, table):
    lin, region = ahb_to_linker(node.byte_addr, table.image)
    return '0x%06x' % node.byte_addr, ('0x%06x' % lin if lin is not None
                                       else '   -   '), region or '?'


def parse_int(text):
    text = text.strip()
    return int(text, 16) if text.lower().startswith('0x') else int(text, 0)


def enum_label(node, value):
    return node.constants().get(value)


# ----------------------------------------------------------------- commands

def cmd_info(args):
    table = load(args.image, args.dir)
    print('file      : %s' % table.file)
    print('image     : %s (%s)' % (table.image, table.name))
    print('globals   : %d' % len(table.globals))
    print('nodes     : %d   named paths: %d' % (table.nodes,
                                                len(table.by_path)))
    fields = sum(1 for n in table.walk() if n.kind == 'field')
    consts = sum(1 for n in table.walk() if n.enum_value is not None)
    print('bitfields : %d   enum constants: %d' % (fields, consts))

    per = {}
    outside = []
    for n in table.globals:
        lin, region = ahb_to_linker(n.byte_addr, table.image)
        if region is None:
            outside.append(n)
        per[region] = per.get(region, 0) + 1
    print('\nglobals by region (AHB address -> %s map):' % CHIP)
    for region, count in sorted(per.items(), key=lambda kv: -kv[1]):
        lo = min(g.byte_addr for g in table.globals
                 if ahb_to_linker(g.byte_addr, table.image)[1] == region)
        hi = max(g.byte_addr + max(g.size_bytes, 1) for g in table.globals
                 if ahb_to_linker(g.byte_addr, table.image)[1] == region)
        print('  %-14s %4d   0x%06x .. 0x%06x' % (region, count, lo, hi))
    if outside:
        print('  !! %d globals outside every known region' % len(outside))
        return 1
    return 0


def cmd_regions(args):
    print('%-14s %-21s %-21s %s' % ('region', 'linker', 'AHB', 'kind'))
    for lo, hi, ahb, name, is_fw in REGIONS:
        print('%-14s 0x%06x..0x%06x  0x%06x..0x%06x  %s' % (
            name, lo, hi, ahb, ahb + (hi - lo), 'fw' if is_fw else 'ucode'))
    print('\nmem_addr (debugfs) takes a *linker* address and only reaches '
          'regions marked fw;\nAHB addresses 0x900000..0xa80000 reach the '
          'same memory through the identity\nmapping of "upper", ucode '
          'included.')
    return 0


def cmd_list(args):
    table = load(args.image, args.dir)
    nodes = table.match(args.pattern, tops_only=not args.all)
    for n in sorted(nodes, key=lambda n: (n.byte_addr, n.path)):
        ahb, lin, region = fmt_addr(n, table)
        size = '%4d B' % n.size_bytes if not n.is_bitfield else '%6s' % fmt_bits(n)
        print('%s  %s  %-12s %s  %s' % (ahb, lin, region, size, n.path))
    print('\n%d symbol(s)' % len(nodes))
    return 0


def _show(node, table, views, mem, indent=0, maxdepth=99):
    ahb, lin, _region = fmt_addr(node, table)
    consts = node.constants()
    value = mem.value(node) if mem else None
    val = ''
    if value is not None:
        val = '  = 0x%x' % value
        if consts.get(value) is not None:
            val += ' (%s)' % consts[value]
        elif node.width <= 32:
            val += ' (%d)' % value
    kind = 'field' if node.kind == 'field' else ''
    print('%s%s %s %-7s %-6s %s%s' % ('  ' * indent, ahb, lin, fmt_bits(node),
                                      kind, node.label, val))
    if consts:
        for v in sorted(consts):
            print('%s    %-10s = %d (0x%x)' % ('  ' * indent, consts[v], v, v))
        return
    if indent >= maxdepth:
        return
    kids = node.eff_kids() if views else node.unique_kids()
    for k in kids:
        _show(k, table, views, mem, indent + 1, maxdepth)


def cmd_show(args):
    table = load(args.image, args.dir)
    mem = Memory.from_fw(args.values) if args.values else None
    node = table.resolve(args.name)
    print('%-8s %-8s %-7s %-6s %s' % ('AHB', 'linker', 'bits', 'kind', 'name'))
    _show(node, table, args.views, mem, 0, args.depth)
    return 0


def cmd_resolve(args):
    table = load(args.image, args.dir)
    for query in args.path:
        node = table.resolve(query)
        ahb, lin, region = fmt_addr(node, table)
        print('symbol    : %s' % node.path)
        print('AHB       : %s   linker: %s   region: %s' % (ahb, lin, region))
        print('bits      : %s  width %d  size %d B' % (fmt_bits(node),
                                                       node.width,
                                                       node.size_bytes))
        acc = node.access()
        if acc:
            dw, shift, mask = acc
            print('dword     : 0x%06x  shift %d  mask 0x%08x' % (dw, shift,
                                                                 mask))
            print('peek      : echo 0x%06x > $D/mem_addr && cat $D/mem_val'
                  % dw)
        else:
            print('access    : %d bytes at 0x%06x (too wide for one dword)'
                  % (node.size_bytes, node.byte_addr))
            print('peek      : dd if=$D/blob_%s bs=1 skip=%d count=%d'
                  % (region, node.byte_addr - _region_base(region),
                     node.size_bytes))
        consts = node.constants()
        if consts:
            print('values    : %s' % ', '.join(
                '%s=%d' % (consts[v], v) for v in sorted(consts)))
        print()
    return 0


def _region_base(region):
    for lo, hi, ahb, name, _is_fw in REGIONS:
        if name == region:
            return ahb
    return 0


def cmd_at(args):
    table = load(args.image, args.dir)
    addr = parse_int(args.addr)
    if args.linker:
        ahb, region = linker_to_ahb(addr)
        if ahb is None:
            raise SymError('0x%x is in no linker region' % addr)
        print('linker 0x%06x -> AHB 0x%06x (%s)\n' % (addr, ahb, region))
        addr = ahb
    hits = table.at(addr, args.bit)
    if not hits:
        lin, region = ahb_to_linker(addr, table.image)
        print('nothing at 0x%06x (region %s)' % (addr, region or '?'))
        return 1
    for n in hits:
        print('%s %-7s %-5s %s' % (fmt_addr(n, table)[0], fmt_bits(n),
                                   'field' if n.kind == 'field' else '',
                                   n.path))
    return 0


def _memory(args):
    if args.dump:
        if args.base is None:
            raise SymError('--dump needs --base with the region address, '
                           'e.g. --base 0xa00000 for blob_fw_data')
        return Memory.from_dump(args.dump, parse_int(args.base))
    return Memory.from_fw(args.image_file)


def cmd_read(args):
    table = load(args.image, args.dir)
    mem = _memory(args)
    rc = 0
    for query in args.path:
        node = table.resolve(query)
        value = mem.value(node)
        if value is None:
            print('%-50s  -- not in %s' % (node.path, mem.describe()))
            rc = 1
            continue
        consts = node.constants()
        label = consts.get(value)
        if node.size_bytes > 8:
            raw = mem.read(node.byte_addr, node.size_bytes)
            print('%-50s  %d bytes  %s%s' % (node.path, node.size_bytes,
                                             raw[:16].hex(),
                                             '...' if len(raw) > 16 else ''))
            continue
        print('%-50s  0x%0*x  %-12d%s' % (
            node.path, max(2, (node.width + 3) // 4), value, value,
            '  ' + label if label else ''))
    return rc


def cmd_dump(args):
    table = load(args.image, args.dir)
    mem = _memory(args)
    shown = missing = 0
    for node in sorted(table.match(args.pattern), key=lambda n: n.byte_addr):
        value = mem.value(node)
        if value is None:
            missing += 1
            continue
        shown += 1
        consts = node.constants()
        if node.size_bytes > 8:
            raw = mem.read(node.byte_addr, node.size_bytes)
            text = '%d B  %s%s' % (node.size_bytes, raw[:12].hex(),
                                   '..' if len(raw) > 12 else '')
        else:
            text = '0x%x' % value
            if consts.get(value) is not None:
                text += '  %s' % consts[value]
            elif node.width <= 32:
                text += '  (%d)' % value
        print('0x%06x  %-46s %s' % (node.byte_addr, node.name, text))
    print('\n%d read, %d outside the image' % (shown, missing))
    return 0


def _fw_segments(records):
    """Loadable data records as (ahb_addr, container_data_offset, size)."""
    segs = []
    for rec in records:
        if rec['type'] == 2 and len(rec['payload']) >= 4:
            addr = struct.unpack_from('<I', rec['payload'], 0)[0]
            data_off = rec['offset'] + 8 + 4          # head + addr field
            segs.append((addr, data_off, len(rec['payload']) - 4))
    return segs


def _rewrite_crc(blob, hdr, out):
    blob = bytes(blob)
    fixed = wil_brd.compute_crc(blob, hdr['data_len'])
    blob = blob[:16] + struct.pack('<I', fixed) + blob[20:]
    with open(out, 'wb') as fh:
        fh.write(blob)
    return fixed


def cmd_segments(args):
    _blob, _hdr, records = wil_brd.load(args.image_file)
    print('%-10s %-10s %-10s %8s  region' % ('AHB', 'linker', 'file-off',
                                             'bytes'))
    for addr, off, size in _fw_segments(records):
        lin, region, _ex = region_for_segment(addr)
        print('0x%08x 0x%08x 0x%08x %8d  %s'
              % (addr, lin if lin is not None else 0, off, size,
                 region or '?'))
    return 0


def cmd_patch(args):
    """Overwrite a byte range of an image by AHB address, fix the crc.

    The bytes come from --bytes (hex), --from FILE, or an overlay file of
    `addr: hexbytes` lines (--overlay); the last is what
    `arc_export_patch.py` writes out of Ghidra.
    """
    blob, hdr, records = wil_brd.load(args.image_file)
    blob = bytearray(blob)
    segs = _fw_segments(records)

    edits = []          # (addr, bytes)
    if args.overlay:
        for ln, line in enumerate(open(args.overlay), 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            a, _, hexs = line.partition(':')
            try:
                edits.append((parse_int(a), bytes.fromhex(hexs.strip()
                                                          .replace(' ', ''))))
            except ValueError:
                raise SymError('%s:%d: bad overlay line %r'
                               % (args.overlay, ln, line))
    else:
        if args.addr is None:
            raise SymError('need --addr with --bytes/--from (or --overlay)')
        if args.from_file:
            data = open(args.from_file, 'rb').read()
        elif args.bytes:
            data = bytes.fromhex(args.bytes.replace(' ', ''))
        else:
            raise SymError('need --bytes or --from')
        edits.append((parse_int(args.addr), data))

    total = 0
    for addr, data in edits:
        for base, off, size in segs:
            if base <= addr and addr + len(data) <= base + size:
                where = off + (addr - base)
                break
        else:
            raise SymError('0x%06x..0x%06x is not inside one data record'
                           % (addr, addr + len(data)))
        before = bytes(blob[where:where + len(data)])
        changed = sum(1 for a, b in zip(before, data) if a != b)
        blob[where:where + len(data)] = data
        total += changed
        lin, region = ahb_to_linker(addr, args.image)
        print('0x%08x  %-12s %d byte(s), %d changed' % (addr, region or '?',
                                                        len(data), changed))

    print('\n%d byte(s) changed across %d edit(s)' % (total, len(edits)))
    if args.dry_run:
        print('dry run, nothing written')
        return 0
    out = args.output or args.image_file
    fixed = _rewrite_crc(blob, hdr, out)
    print('written %s, crc -> 0x%08x' % (out, fixed))
    return 0


def cmd_poke(args):
    """Patch an image in place, by symbol name."""
    table = load(args.image, args.dir)
    blob, hdr, records = wil_brd.load(args.image_file)
    blob = bytearray(blob)
    segs = _fw_segments(records)

    touched = 0
    for item in args.assignment:
        if '=' not in item:
            raise SymError('expected NAME=VALUE, got %r' % item)
        name, _, text = item.partition('=')
        node = table.resolve(name.strip())
        consts = {v: k for k, v in node.constants().items()}
        value = consts[text.strip()] if text.strip() in consts \
            else parse_int(text)
        if node.width <= 0 or node.width > 32:
            raise SymError('%s is %d bits wide, poke handles up to 32'
                           % (node.path, node.width))
        if value >> node.width:
            raise SymError('%d does not fit in %d bits (%s)'
                           % (value, node.width, node.path))
        for base, off, size in segs:
            if base <= node.byte_addr and \
                    node.byte_addr + node.size_bytes <= base + size:
                where = off + (node.byte_addr - base)
                break
        else:
            raise SymError('%s (0x%06x) is not in %s'
                           % (node.path, node.byte_addr, args.image_file))
        before = bytes(blob[where:where + node.size_bytes])
        old = int.from_bytes(before, 'little')
        shift = node.bit0 % 8
        mask = ((1 << node.width) - 1) << shift
        new = (old & ~mask) | (value << shift)
        after = new.to_bytes(node.size_bytes, 'little')
        blob[where:where + node.size_bytes] = after
        touched += sum(1 for a, b in zip(before, after) if a != b)
        print('%-46s 0x%06x  0x%x -> 0x%x' % (node.path, node.byte_addr,
                                              (old & mask) >> shift, value))

    print('\n%d byte(s) changed' % touched)
    if args.dry_run:
        print('dry run, nothing written')
        return 0
    out = args.output or args.image_file
    fixed = _rewrite_crc(blob, hdr, out)
    print('\nwritten %s, crc -> 0x%08x' % (out, fixed))
    return 0


# ----------------------------------------------------------- project kit

def cmd_project(args):
    """Dump everything a Ghidra project needs to hold the WHOLE image:
    every loadable segment as a raw blob, a manifest, both symbol layouts and
    a build script that creates the blocks, applies the types and analyses."""
    import json
    out = args.output
    os.makedirs(out, exist_ok=True)
    _blob, _hdr, records = wil_brd.load(args.image_file)

    manifest = []
    for addr, off, size in _fw_segments(records):
        _lin, region, is_exec = region_for_segment(addr)
        data = _blob[off:off + size]
        fn = 'seg_%08x.bin' % addr
        with open(os.path.join(out, fn), 'wb') as fh:
            fh.write(data)
        manifest.append({'addr': addr, 'file': fn, 'size': size,
                         'region': region or '?', 'exec': bool(is_exec)})
    entry = fw_code_base()
    with open(os.path.join(out, 'segments.json'), 'w') as fh:
        json.dump(manifest, fh, indent=1)
    with open(os.path.join(out, 'project.json'), 'w') as fh:
        json.dump({'chip': CHIP, 'entry': entry,
                   'has_globals': None}, fh, indent=1)

    # both layouts (fw + ucode) so data gets typed everywhere -- only if this
    # chip has symbol maps (Talyn does; Sparrow ships none)
    have_globals = False
    globals_ok = CHIP in ('talyn', 'talyn-mb') or args.dir
    for image in (('fw', 'ucode') if globals_ok else ()):
        try:
            table = load(image, args.dir)
        except SymError:
            continue
        have_globals = True
        extra = []
        entries = [_json_node(n, table, extra) for n in
                   sorted(table.globals, key=lambda n: n.byte_addr)]
        with open(os.path.join(out, 'layout_%s.json' % image), 'w') as fh:
            json.dump({'image': image, 'chip': CHIP,
                       'globals': entries + extra}, fh, indent=1)
    if have_globals:
        with open(os.path.join(out, 'wil_apply_globals.py'), 'w') as fh:
            fh.write(GHIDRA_SCRIPT)
    tpl = os.path.join(HERE, 'ghidra')
    for name in ('wil_build_project.py', 'arc_export_patch.py'):
        src = os.path.join(tpl, name)
        if os.path.exists(src):
            with open(src) as r, open(os.path.join(out, name), 'w') as w:
                w.write(r.read())
        else:
            print('  (note: %s not found in %s)' % (name, tpl))

    print('segments      : %d blobs + segments.json' % len(manifest))
    for m in manifest:
        print('  0x%08x  %-10s %8d B  %s' % (m['addr'], m['region'],
                                             m['size'],
                                             'code' if m['exec'] else 'data'))
    if have_globals:
        print('layouts       : layout_fw.json, layout_ucode.json')
    else:
        print('layouts       : none (no symbol maps for chip %r) -- code and '
              'blocks only, no data types' % CHIP)
    print('scripts       : wil_build_project.py (loader+types+analyse), '
          'arc_export_patch.py' + (', wil_apply_globals.py'
                                   if have_globals else ''))
    print('\nbuild the project (Ghidra 12.x, ARCompact installed):')
    print('  G=<ghidra>')
    print('  python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py '
          '$G --headless \\')
    print('    PROJ fw -import %s/seg_%08x.bin \\' % (out, entry))
    print('    -loader BinaryLoader -loader-baseAddr 0x%06x \\' % entry)
    print('    -processor "ARCompact:LE:32:default" \\')
    print('    -noanalysis -scriptPath %s \\' % out)
    print('    -preScript wil_build_project.py %s' % out)
    return 0


# ------------------------------------------------------------ ghidra export

def detached(parent, kid):
    """True when a child does not lie inside its parent's span.

    The vendor's map follows pointers: a pointer member is expanded in
    place, but at the address of the object it points to.  37 nodes across
    the two files are like this -- state_names, event_names, memory pools --
    and they are separate objects, not members.
    """
    if kid.width <= 0 or parent.width <= 0:
        return False
    return (kid.bit0 < parent.bit0
            or kid.bit0 + kid.width > parent.bit0 + parent.width)


def _json_node(node, table, extra=None):
    """One node as a plain dict; children already collapsed."""
    out = {
        'name': node.name,
        'path': node.path,
        'addr': node.byte_addr,
        'bit': node.bit0 % 8,
        'width': node.width,
        'size': node.size_bytes,
        'kind': node.kind,
    }
    consts = node.constants()
    if consts:
        out['enum'] = {str(v): n for v, n in consts.items()}
        return out
    kids = []
    for k in node.unique_kids():
        if extra is not None and detached(node, k):
            item = _json_node(k, table, extra)
            item['name'] = k.path.replace('.', '__').replace('[', '_') \
                            .replace(']', '')
            item['origin'] = 'pointee'
            extra.append(item)
            continue
        kids.append(_json_node(k, table, extra))
    if kids:
        out['kids'] = kids
    return out


def cmd_ghidra(args):
    import json
    table = load(args.image, args.dir)
    out = args.output
    os.makedirs(out, exist_ok=True)
    stem = 'wil_%s' % table.image

    # 1. flat symbol list, the format ImportSymbolsScript.java expects
    sym_path = os.path.join(out, stem + '_symbols.txt')
    n_syms = 0
    with open(sym_path, 'w') as fh:
        for n in sorted(table.globals, key=lambda n: n.byte_addr):
            fh.write('%s 0x%06x\n' % (n.name, n.byte_addr))
            n_syms += 1
        if args.leaves:
            for n in sorted(table.walk(), key=lambda n: (n.byte_addr, n.path)):
                if n.enum_value is not None or n.eff_kids() or n.transparent:
                    continue
                if n.path.count('.') == 0:
                    continue
                fh.write('%s 0x%06x\n' % (n.path.replace('.', '__')
                                          .replace('[', '_').replace(']', ''),
                                          n.byte_addr))
                n_syms += 1

    # 2. full layout for the type-building script
    extra = []
    entries = [_json_node(n, table, extra) for n in
               sorted(table.globals, key=lambda n: n.byte_addr)]
    layout = {
        'image': table.image,
        'chip': CHIP,
        'source': os.path.abspath(table.file),
        'globals': entries + extra,
    }
    lay_path = os.path.join(out, stem + '_layout.json')
    with open(lay_path, 'w') as fh:
        json.dump(layout, fh, indent=1)

    # 3. memory map: regions, plus the segments of a real image if given
    mem_path = os.path.join(out, stem + '_memory.csv')
    segs = Memory.from_fw(args.fw).segments if args.fw else []
    with open(mem_path, 'w') as fh:
        fh.write('name,ahb_start,ahb_end,linker_start,kind,image_bytes\n')
        for lo, hi, ahb, name, is_fw in REGIONS:
            have = 0
            for base, data in segs:
                lo_ov = max(base, ahb)
                hi_ov = min(base + len(data), ahb + (hi - lo))
                have += max(0, hi_ov - lo_ov)
            fh.write('%s,0x%06x,0x%06x,0x%06x,%s,%d\n'
                     % (name, ahb, ahb + (hi - lo), lo,
                        'fw' if is_fw else 'ucode', have))

    # 4. the script itself
    script_path = os.path.join(out, 'wil_apply_globals.py')
    with open(script_path, 'w') as fh:
        fh.write(GHIDRA_SCRIPT)

    print('%-28s %d symbols' % (os.path.basename(sym_path), n_syms))
    print('%-28s %d globals with full layout%s'
          % (os.path.basename(lay_path), len(entries),
             ', %d pointed-to objects' % len(extra) if extra else ''))
    print('%-28s %d regions%s' % (os.path.basename(mem_path), len(REGIONS),
                                  ', image segments measured' if segs else ''))
    print('%-28s Ghidra (Jython) script' % os.path.basename(script_path))
    print('\nload the image first, then run the script and point it at '
          '%s' % os.path.basename(lay_path))
    return 0


GHIDRA_SCRIPT = '''# Apply wil6210/Talyn firmware globals to the current program.
#
# Generated by wil_syms.py (SparRAW-tools).  Run it on a program that already
# holds the image at its AHB addresses -- the .fw data records are loaded
# at 0x900000 (fw_code), 0xa00000 (fw_data), 0xa20000 (fw_peri),
# 0xa38000 (uc_code) and 0xa78000 (uc_data).
#
# What it does: labels every global, builds a data type for it out of the
# vendor's layout (structs, unions, arrays, bitfields, enums) and applies
# that type at the address.  Types land in /wil6210.
#
# Headless:
#   analyzeHeadless PROJDIR proj -process IMAGE \
#       -scriptPath DIR -postScript wil_apply_globals.py DIR/wil_fw_layout.json
#
# Runs both on Jython (Ghidra <= 11) and on PyGhidra (Ghidra 11.3+, the only
# option in 12.x -- there the headless launcher is
# Ghidra/Features/PyGhidra/support/pyghidra_launcher.py --headless).
#
# @category wil6210
# @runtime PyGhidra

import json

from ghidra.program.model.data import (StructureDataType, UnionDataType,
                                       ArrayDataType, EnumDataType,
                                       ByteDataType, WordDataType,
                                       DWordDataType, QWordDataType,
                                       UnsignedLongLongDataType,
                                       CategoryPath, DataTypeConflictHandler)
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet

CAT = CategoryPath('/wil6210')

SCALARS = {1: ByteDataType(), 2: WordDataType(), 4: DWordDataType(),
           8: QWordDataType()}

try:                     # Jython 2.7 (Ghidra <= 11) vs PyGhidra (Ghidra 12)
    BIG = long
except NameError:
    BIG = int


def scalar(size):
    return SCALARS.get(size)


def uniq(name, used):
    """Ghidra data type names must be unique inside a category."""
    base = name.replace('<', '_').replace('>', '_').replace(' ', '_')
    if base not in used:
        used.add(base)
        return base
    i = 2
    while '%s_%d' % (base, i) in used:
        i += 1
    used.add('%s_%d' % (base, i))
    return '%s_%d' % (base, i)


def build(node, dtm, used, hint=None):
    """Node -> DataType, or None when the node is a plain scalar."""
    kids = node.get('kids')
    name = hint or node['name']
    if node.get('enum'):
        size = max(1, (node['width'] + 7) // 8)
        if size not in (1, 2, 4, 8):
            size = 4
        e = EnumDataType(CAT, uniq(name + '_e', used), size)
        for value, cname in node['enum'].items():
            e.add(str(cname), BIG(value))
        return dtm.addDataType(e, DataTypeConflictHandler.KEEP_HANDLER)
    if not kids:
        return scalar(node['size'])

    # array: every child is an index of the same size
    names = [k['name'] for k in kids]
    if len(kids) > 1 and all(n.startswith('<') and n.endswith('>')
                             for n in names):
        elem = build(kids[0], dtm, used, name + '_elem') \
            or scalar(kids[0]['size'])
        if elem is None:
            return None
        return ArrayDataType(elem, len(kids), elem.getLength())

    # union when children overlap in bits, struct otherwise
    spans = sorted((k['addr'] * 8 + k['bit'], k['width']) for k in kids)
    overlap = any(spans[i][0] + spans[i][1] > spans[i + 1][0]
                  for i in range(len(spans) - 1))
    base_bit = node['addr'] * 8 + node['bit']

    if overlap:
        u = UnionDataType(CAT, uniq(name, used))
        for k in kids:
            dt = build(k, dtm, used) or scalar(max(1, k['size']))
            if dt is None:
                continue
            u.add(dt, k['name'], 'bits %d..%d' % (k['bit'],
                                                  k['bit'] + k['width'] - 1))
        dtu = dtm.addDataType(u, DataTypeConflictHandler.KEEP_HANDLER)
        if dtu.getLength() >= node['size']:
            return dtu
        # the node is declared wider than its widest member (the tail is
        # unnamed in the map): keep the declared size
        box = StructureDataType(CAT, uniq(name + '_box', used), node['size'])
        box.replaceAtOffset(0, dtu, dtu.getLength(), name, None)
        return dtm.addDataType(box, DataTypeConflictHandler.KEEP_HANDLER)

    s = StructureDataType(CAT, uniq(name, used), node['size'])
    for k in kids:
        off_bits = (k['addr'] * 8 + k['bit']) - base_bit
        dt = build(k, dtm, used)
        if k['width'] % 8 or off_bits % 8 or (dt is None and
                                              k['size'] not in (1, 2, 4, 8)):
            try:
                s.insertBitFieldAt(off_bits // 8, max(1, k['size']),
                                   off_bits % 8,
                                   dt or ByteDataType(), k['width'],
                                   k['name'], None)
            except Exception as exc:
                print('  bitfield %s skipped: %s' % (k['path'], exc))
            continue
        dt = dt or scalar(k['size'])
        if dt is None:
            continue
        try:
            s.replaceAtOffset(off_bits // 8, dt, dt.getLength(), k['name'],
                              None)
        except Exception as exc:
            print('  member %s skipped: %s' % (k['path'], exc))
    return dtm.addDataType(s, DataTypeConflictHandler.KEEP_HANDLER)


def run():
    args = getScriptArgs()
    if args:
        path = args[0]
    else:
        path = askFile('wil_*_layout.json from wil_syms.py ghidra',
                       'Open').getAbsolutePath()
    layout = json.loads(open(path).read())
    dtm = currentProgram.getDataTypeManager()
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    used = set()
    labelled = typed = skipped = clash = 0
    listing = currentProgram.getListing()

    # Real globals first; the pointed-to objects the map carries come with a
    # nominal length and overlap each other, so they are only applied where
    # they do not collide with something already defined.
    entries = [g for g in layout['globals'] if g.get('origin') != 'pointee']
    entries += [g for g in layout['globals'] if g.get('origin') == 'pointee']

    for g in entries:
        addr = space.getAddress(g['addr'])
        if currentProgram.getMemory().getBlock(addr) is None:
            skipped += 1
            continue
        createLabel(addr, g['name'], True, SourceType.IMPORTED)
        labelled += 1
        try:
            dt = build(g, dtm, used)
            if dt is None:
                continue
            end = addr.add(max(0, dt.getLength() - 1))
            if currentProgram.getMemory().getBlock(end) is None:
                skipped += 1
                continue
            span = AddressSet(addr, end)
            if listing.getDefinedData(span, True).hasNext():
                clash += 1
                continue
            createData(addr, dt)
            typed += 1
        except Exception as exc:
            print('%s: %s' % (g['name'], exc))

    print('wil6210 globals: %d labelled, %d typed, %d outside memory, '
          '%d left alone (address already taken)'
          % (labelled, typed, skipped, clash))


run()
'''


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dir', help='directory with the *_globals.xml files '
                                  '(default: %s)' % DEFAULT_GLOBALS)
    ap.add_argument('--image', choices=sorted(FILES), default='fw',
                    help='which symbol map to use (default: fw)')
    ap.add_argument('--chip', choices=sorted(CHIPS), default='talyn-mb',
                    help='remapping table (default: talyn-mb, the chip both '
                         'globals files describe)')
    sub = ap.add_subparsers(dest='cmd')

    p = sub.add_parser('info', help='counts and the regions the globals live in')
    p.set_defaults(func=cmd_info)

    p = sub.add_parser('regions', help='linker <-> AHB translation table')
    p.set_defaults(func=cmd_regions)

    p = sub.add_parser('list', help='list globals')
    p.add_argument('pattern', nargs='?', help='glob over names and paths')
    p.add_argument('--all', action='store_true',
                   help='every named node, not just the globals')
    p.set_defaults(func=cmd_list)

    p = sub.add_parser('show', help='layout of one symbol')
    p.add_argument('name')
    p.add_argument('--depth', type=int, default=99)
    p.add_argument('--values', metavar='IMAGE.fw',
                   help='fill the tree with the values from an image')
    p.add_argument('--views', action='store_true',
                   help='keep every union view; by default the duplicate '
                        'typedef views of the same bits are folded')
    p.set_defaults(func=cmd_show)

    p = sub.add_parser('resolve', help='address, bits and mask of a symbol')
    p.add_argument('path', nargs='+')
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser('at', help='what lives at an address')
    p.add_argument('addr')
    p.add_argument('--bit', type=int, help='narrow down to one bit')
    p.add_argument('--linker', action='store_true',
                   help='the address is a linker address, not AHB')
    p.set_defaults(func=cmd_at)

    for name, help_text, func in (
            ('read', 'values of named symbols from an image or a dump',
             cmd_read),
            ('dump', 'values of every global from an image or a dump',
             cmd_dump)):
        p = sub.add_parser(name, help=help_text)
        p.add_argument('image_file', nargs='?', metavar='IMAGE.fw',
                       help='a .fw container')
        if name == 'read':
            p.add_argument('path', nargs='+')
        else:
            p.add_argument('pattern', nargs='?')
        p.add_argument('--dump', metavar='FILE',
                       help='raw region dump instead, e.g. debugfs blob_fw_data')
        p.add_argument('--base', help='AHB address the dump starts at')
        p.set_defaults(func=func)

    p = sub.add_parser('segments',
                       help='loadable data records of an image (for patching)')
    p.add_argument('image_file', metavar='IMAGE.fw')
    p.set_defaults(func=cmd_segments)

    p = sub.add_parser('patch',
                       help='overwrite a byte range by AHB address, fix crc')
    p.add_argument('image_file', metavar='IMAGE.fw')
    p.add_argument('--addr', help='AHB address to write at')
    p.add_argument('--bytes', help='replacement bytes, hex (e.g. 00207814)')
    p.add_argument('--from', dest='from_file', metavar='FILE',
                   help='take the replacement bytes from a file')
    p.add_argument('--overlay', metavar='FILE',
                   help='apply many edits: lines of "addr: hexbytes" '
                        '(what arc_export_patch.py writes)')
    p.add_argument('-o', '--output', help='write here instead of in place')
    p.add_argument('-n', '--dry-run', action='store_true')
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser('poke', help='patch an image by symbol name')
    p.add_argument('image_file', metavar='IMAGE.fw')
    p.add_argument('assignment', nargs='+', metavar='NAME=VALUE')
    p.add_argument('-o', '--output', help='write here instead of in place')
    p.add_argument('-n', '--dry-run', action='store_true')
    p.set_defaults(func=cmd_poke)

    p = sub.add_parser('project',
                       help='dump a full-image Ghidra project kit (all '
                            'segments + types + build script)')
    p.add_argument('image_file', metavar='IMAGE.fw')
    p.add_argument('-o', '--output', required=True, metavar='DIR')
    p.set_defaults(func=cmd_project)

    p = sub.add_parser('ghidra', help='export symbols, layout and memory map')
    p.add_argument('-o', '--output', required=True, metavar='DIR')
    p.add_argument('--fw', metavar='IMAGE.fw',
                   help='measure how much of each region the image fills')
    p.add_argument('--leaves', action='store_true',
                   help='also export every leaf as name__member')
    p.set_defaults(func=cmd_ghidra)

    args = ap.parse_args()
    if not getattr(args, 'func', None):
        ap.print_help()
        return 2
    set_chip(args.chip)
    try:
        return args.func(args) or 0
    except SymError as exc:
        sys.stderr.write('error: %s\n' % exc)
        return 2
    except wil_brd.BadImage as exc:
        sys.stderr.write('error: %s\n' % exc)
        return 2


if __name__ == '__main__':
    sys.exit(main())
