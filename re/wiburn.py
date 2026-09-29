#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Python side of wiburn: the wiburn INI format and board-file images.

Covers the offline, file-level half of the C++ wiburn tool:

  * the INI lexer/parser, faithful to ini_parser.cpp (get_clean_line + init)
  * board images: the [production] section is a flat sequence of
    (address, value) little-endian dword pairs -- verified byte exact
    against the shipped Talyn board files
  * conversion to and from the .brd container (via wil_brd.py)

Also covers the flash image side: pointer table, section headers and CRCs,
the TLV tags of image_info / usb_info, the ids section, the 4 KB section
layout policy, and the [reg_tree] / [fw_symbols] / [ucode_symbols] translation
maps.  Not covered (needs the device): -burn / -read / -erase over PCI or USB.
"""

import argparse
import os
import struct
import sys

import wil_brd

# Board images end with an optional terminator pair followed by an opaque
# dword.  Its derivation is unknown: it is not a CRC of the payload under
# any common parameter set, and several shipped files carry plain zeros
# there.  It is therefore preserved verbatim rather than recomputed.
TERMINATOR = (0xffffffff, 0xffffffff)
DEFAULT_BRD_ADDR = 0x00a2f800
TRAILER_TAG = ';;trailer='


class IniError(Exception):
    pass


# ------------------------------------------------------------------ ini

def clean_line(line):
    """Reproduce ini_parser.cpp::get_clean_line.

    Lower cases, turns a leading '[' and its ']' into spaces, turns '=' into
    a space and truncates at the first '#' or ';'.
    """
    out = []
    alpha_seen = False
    section = False
    for ch in line:
        if 'A' <= ch <= 'Z':
            ch = ch.lower()
        if 'a' <= ch <= 'z':
            alpha_seen = True
        if ch == '\n':
            break
        if ch == '[' and not alpha_seen:
            section = True
            out.append(' ')
        elif ch == ']' and section:
            out.append(' ')
        elif ch == '=':
            out.append(' ')
        elif ch in '#;':
            break
        else:
            out.append(ch)
    return ''.join(out)


def parse_ini(path):
    """Return [(section_name, [(key, value), ...]), ...] in file order.

    Mirrors the C++ token rules: one token starts a section, two tokens are
    key/value, three tokens make the key 'a1#a3', four tokens are a
    translation-map entry (kept as a raw tuple).
    """
    sections = []
    current = None
    trailer = None
    with open(path) as fh:
        for raw in fh:
            if raw.lstrip().startswith(TRAILER_TAG):
                trailer = int(raw.split('=', 1)[1].strip(), 16)
            tokens = clean_line(raw).split()
            if not tokens:
                continue
            if len(tokens) == 1:
                current = (tokens[0], [])
                sections.append(current)
            elif current is None:
                raise IniError('key/value line before any section: %r' % raw.strip())
            elif len(tokens) == 2:
                current[1].append((tokens[0], tokens[1]))
            elif len(tokens) == 3:
                current[1].append((tokens[0] + '#' + tokens[2], tokens[1]))
            else:
                current[1].append((tokens[0], tuple(tokens[1:4])))
    return sections, trailer


def get_section(sections, name):
    name = name.lower()
    for sec_name, entries in sections:
        if sec_name == name:
            return entries
    return None


def to_int(text):
    try:
        return int(text, 0)
    except ValueError:
        raise IniError('not a number: %r' % text)


# ---------------------------------------------------------------- board

def pairs_from_ini(path, section='production'):
    sections, trailer = parse_ini(path)
    entries = get_section(sections, section)
    if entries is None:
        available = ', '.join(s for s, _ in sections) or '(none)'
        raise IniError('no [%s] section; file has: %s' % (section, available))
    pairs = []
    for key, value in entries:
        if isinstance(value, tuple):
            raise IniError('unexpected translation-map line in [%s]' % section)
        pairs.append((to_int(key), to_int(value)))
    return pairs, trailer


def pairs_to_blob(pairs, trailer=None, terminator=False):
    if terminator and (not pairs or pairs[-1] != TERMINATOR):
        pairs = list(pairs) + [TERMINATOR]
    blob = b''.join(struct.pack('<II', a & 0xffffffff, v & 0xffffffff)
                    for a, v in pairs)
    if trailer is not None:
        blob += struct.pack('<I', trailer & 0xffffffff)
    return blob


def blob_to_pairs(blob):
    """Split a board image into dword pairs plus any odd trailing dword."""
    n_pairs = len(blob) // 8
    pairs = list(struct.unpack('<%dI' % (n_pairs * 2), blob[:n_pairs * 8]))
    pairs = list(zip(pairs[0::2], pairs[1::2]))
    rest = blob[n_pairs * 8:]
    trailer = None
    if len(rest) == 4:
        trailer = struct.unpack('<I', rest)[0]
    elif rest:
        raise IniError('trailing %d bytes, expected 0 or 4' % len(rest))
    return pairs, trailer


def write_ini(path, pairs, trailer=None, section='PRODUCTION'):
    with open(path, 'w') as fh:
        fh.write('[%s]\n' % section)
        for addr, value in pairs:
            comment = ''
            if (addr, value) == TERMINATOR:
                comment = ' ;; end of table'
            fh.write('0x%08X = 0x%08X%s\n' % (addr, value, comment))
        if trailer is not None:
            fh.write('\n%s0x%08X\n' % (TRAILER_TAG, trailer))


# ------------------------------------------------------------- commands

def cmd_ini2bin(args):
    pairs, trailer = pairs_from_ini(args.ini, args.section)
    if args.trailer is not None:
        trailer = to_int(args.trailer)
    blob = pairs_to_blob(pairs, trailer, args.terminator)
    with open(args.output, 'wb') as fh:
        fh.write(blob)
    print('%d pairs%s -> %s (%d bytes)'
          % (len(pairs), '' if trailer is None else ' + trailer', args.output, len(blob)))
    return 0


def cmd_bin2ini(args):
    with open(args.bin, 'rb') as fh:
        blob = fh.read()
    pairs, trailer = blob_to_pairs(blob)
    write_ini(args.output, pairs, trailer, args.section.upper())
    print('%d pairs%s -> %s' % (len(pairs),
          '' if trailer is None else ' + trailer 0x%08X' % trailer, args.output))
    return 0


def cmd_ini2brd(args):
    payloads = []
    for i, ini in enumerate(args.ini):
        pairs, trailer = pairs_from_ini(ini, args.section)
        if args.trailer is not None:
            trailer = args.trailer
        addr = args.addr[i] if i < len(args.addr) else 0
        payloads.append(struct.pack('<I', addr)
                        + pairs_to_blob(pairs, trailer, args.terminator))

    body = bytearray()
    header = wil_brd.FILE_HEADER.pack(wil_brd.SIGNATURE, 0, 0, 1, 0,
                                      args.comment.encode('ascii')[:32].ljust(32, b'\x00'))
    body += wil_brd.HEAD.pack(6, 0, len(header)) + header
    for i, payload in enumerate(payloads):
        if len(payload) % 4:
            raise IniError('record %d payload not 4-aligned' % i)
        flags = args.flags[i] if i < len(args.flags) else 0
        body += wil_brd.HEAD.pack(2, flags, len(payload)) + payload

    data_len = len(body)
    struct.pack_into('<I', body, wil_brd.HEAD.size + 16, data_len)
    crc = wil_brd.compute_crc(bytes(body), data_len)
    struct.pack_into('<I', body, wil_brd.HEAD.size + 8, crc)

    with open(args.output, 'wb') as fh:
        fh.write(bytes(body))
    print('%d data record(s) -> %s (%d bytes, crc 0x%08x)'
          % (len(payloads), args.output, len(body), crc))
    return 0


def cmd_brd2ini(args):
    _, _, records = wil_brd.load(args.brd)
    data_records = [r for r in records if r['type'] == 2]
    if not data_records:
        raise IniError('no data records in %s' % args.brd)

    base = args.output or os.path.splitext(os.path.basename(args.brd))[0]
    written = []
    for i, rec in enumerate(data_records):
        payload = rec['payload']
        addr = struct.unpack_from('<I', payload, 0)[0]
        pairs, trailer = blob_to_pairs(payload[4:])
        out = '%s.ini' % base if len(data_records) == 1 else '%s.rec%d.ini' % (base, i)
        write_ini(out, pairs, trailer)
        written.append(out)
        print('record %d: addr=0x%08x flags=0x%04x  %d pairs%s -> %s'
              % (i, addr, rec['flags'], len(pairs),
                 '' if trailer is None else ' + trailer 0x%08X' % trailer, out))
    print()
    print('to rebuild:')
    print('  wiburn.py ini2brd %s -o rebuilt.brd \\' % ' '.join(written))
    print('      --addr %s --flags %s'
          % (' '.join('0x%08x' % struct.unpack_from('<I', r['payload'], 0)[0]
                      for r in data_records),
             ' '.join('0x%04x' % r['flags'] for r in data_records)))
    return 0


# ---------------------------------------------------------- flash image

# pointers_t from flash_sections.h -- 26 dwords at offset 0 of the image.
POINTER_FIELDS = [
    'signature', 'hw_pointer', 'fw1_pointer', 'fw1_length',
    'fw1_data_pointer', 'fw1_data_length', 'fw2_pointer', 'fw2_length',
    'fw2_data_pointer', 'fw2_data_length', 'production_pointer',
    'ids_pointer', 'pointer_section_version', 'fw1_static_conf_pointer',
    'fw2_static_conf_pointer', 'config_section_pointer', 'image_info_pointer',
    'radio_tx_cnf_pointer', 'radio_rx_cnf_pointer', 'radio_tx_cnf2_pointer',
    'radio_rx_cnf2_pointer', 'raw_data_pointer', 'raw_data_length',
    'usb_pointer', 'usb_info_pointer', 'user_pointer',
]
POINTERS = struct.Struct('<%dI' % len(POINTER_FIELDS))

# section_header_t: BYTE reserved; BYTE section_id; u_int16_t section_size
SECTION_HEADER = struct.Struct('<BBH')

# enum section_id_t from ini_parser_types.h
SECTION_IDS = {
    0: 'production', 1: 'ids', 2: 'hw_conf', 3: 'fw1_code', 4: 'fw1_data',
    5: 'fw2_code', 6: 'fw2_data', 7: 'fw1_static_conf', 8: 'fw2_static_conf',
    9: 'config', 10: 'image_info', 11: 'radio_tx_conf', 12: 'radio_rx_conf',
    13: 'radio_tx_conf2', 14: 'radio_rx_conf2', 15: 'raw_data',
    16: 'usb_info', 17: 'user_conf', 18: 'usb',
}

# pointer fields that address a section; the stored value points at the data,
# i.e. just past section_header_t (see flash_image.cpp::init_ids_section)
SECTION_POINTERS = [
    ('hw_pointer', 'hw_conf'), ('fw1_pointer', 'fw1_code'),
    ('fw1_data_pointer', 'fw1_data'), ('fw2_pointer', 'fw2_code'),
    ('fw2_data_pointer', 'fw2_data'), ('production_pointer', 'production'),
    ('ids_pointer', 'ids'), ('fw1_static_conf_pointer', 'fw1_static_conf'),
    ('fw2_static_conf_pointer', 'fw2_static_conf'),
    ('config_section_pointer', 'config'), ('image_info_pointer', 'image_info'),
    ('radio_tx_cnf_pointer', 'radio_tx_conf'),
    ('radio_rx_cnf_pointer', 'radio_rx_conf'),
    ('radio_tx_cnf2_pointer', 'radio_tx_conf2'),
    ('radio_rx_cnf2_pointer', 'radio_rx_conf2'),
    ('raw_data_pointer', 'raw_data'), ('usb_pointer', 'usb'),
    ('usb_info_pointer', 'usb_info'), ('user_pointer', 'user_conf'),
]

# --- tags, as laid out by info_section_t::write_to_buffer -------------------
# section_header_t, then { tag_header_t, body } ... , end tag, crc32
TAG_HEADER = struct.Struct('<BBH')        # reserved, tag_id, tag_size

TAG_IDS = {1: 'format_version', 2: 'version', 3: 'timestamp',
           4: 'configuration_id', 5: 'device_id', 6: 'hw_id', 0xff: 'end'}
END_TAG_ID = 0xff


def _tag_format_version(body):
    return {'format_version': body[0]}


def _tag_version(body):
    # u32 bitfield: minor:8 major:8 build:13 sub_minor:3
    value = struct.unpack_from('<I', body, 0)[0]
    return {'major': (value >> 8) & 0xff, 'minor': value & 0xff,
            'build': (value >> 16) & 0x1fff, 'sub_minor': (value >> 29) & 0x7,
            'text': '%d.%d.%d.%d' % ((value >> 8) & 0xff, value & 0xff,
                                     (value >> 29) & 0x7, (value >> 16) & 0x1fff)}


def _tag_timestamp(body):
    mn, hour, _, sec, month, day, year = struct.unpack_from('<BBBBBBH', body, 0)
    return {'text': '%04d-%02d-%02d %02d:%02d:%02d'
                    % (year, month, day, hour, mn, sec)}


def _tag_configuration_id(body):
    return {'id': body[:16].hex(),
            'ascii': body[:16].split(b'\x00', 1)[0].decode('ascii', 'replace')}


def _tag_device_id(body):
    device_id, revision_id, misc = struct.unpack_from('<HBB', body, 0)
    return {'device_id': '0x%04x' % device_id, 'revision_id': revision_id,
            'misc': misc}


def _tag_hw_id(body):
    soc, board, antenna, rf, serial, _ = struct.unpack_from('<BBBBHH', body, 0)
    return {'digital_soc_id': soc, 'board_id': board, 'antenna_id': antenna,
            'rf_id': rf, 'serial_id': serial}


TAG_DECODERS = {
    'format_version': (_tag_format_version, 4),
    'version': (_tag_version, 4),
    'timestamp': (_tag_timestamp, 8),
    'configuration_id': (_tag_configuration_id, 16),
    'device_id': (_tag_device_id, 4),
    'hw_id': (_tag_hw_id, 8),
}


def parse_tags(blob, offset, size):
    """Walk the TLV list of an info section; returns [(name, id, fields)]."""
    out = []
    pos = offset + SECTION_HEADER.size
    end = offset + size - 4                     # trailing crc32
    while pos + TAG_HEADER.size <= end:
        _, tag_id, tag_size = TAG_HEADER.unpack_from(blob, pos)
        name = TAG_IDS.get(tag_id, 'tag_0x%02x' % tag_id)
        pos += TAG_HEADER.size
        body = blob[pos:pos + tag_size]
        pos += tag_size
        if tag_id == END_TAG_ID:
            out.append((name, tag_id, {}))
            break
        decoder, need = TAG_DECODERS.get(name, (None, 0))
        if decoder and len(body) >= need:
            out.append((name, tag_id, decoder(body)))
        else:
            out.append((name, tag_id, {'raw': body.hex()}))
    return out


# --- ids section -----------------------------------------------------------
# ini key -> structure field.  wiburn's ini calls board_type simply 'board'.
IDS_INI_KEYS = ['version', 'mac_address', 'ssid', 'local', 'ppm', 'board',
                'lo_power_xif_gc', 'lo_power_stg2_bias', 'vga_bias',
                'vga_stg1_fine_bias', 'ats_ver', 'mlt_ver', 'bl_ver',
                'lo_power_gc_ctrl'] + ['production%d' % i for i in range(1, 17)]
IDS_KEY_TO_FIELD = {'board': 'board_type'}

IDS_SECTION = struct.Struct('<BB6s32sHHHHIHHHHHH' + 'H' * 18)
IDS_FIELDS = ['reserved1', 'version', 'mac_address', 'ssid', 'local',
              'reserved2', 'ppm', 'reserved3', 'board_type',
              'lo_power_xif_gc', 'lo_power_stg2_bias', 'vga_bias',
              'vga_stg1_fine_bias', 'ats_ver', 'mlt_ver', 'bl_ver',
              'lo_power_gc_ctrl'] + ['production%d' % i for i in range(1, 17)]


def section_crc(blob, start, size):
    """CCRC32::CalcCRC over section_size-4 bytes from the section start.

    CCRC32 builds a reflected table from POLYNOMIAL with CRC_MASK init and
    final xor, which is exactly zlib's crc32.
    """
    import zlib
    return zlib.crc32(blob[start:start + size - 4]) & 0xffffffff


def read_pointers(blob):
    if len(blob) < POINTERS.size:
        raise IniError('image shorter than the pointer table (%d bytes)' % len(blob))
    values = POINTERS.unpack_from(blob, 0)
    return dict(zip(POINTER_FIELDS, values))


def walk_sections(blob):
    """Yield one dict per section reachable from the pointer table."""
    pointers = read_pointers(blob)
    seen = set()
    out = []
    for field, name in SECTION_POINTERS:
        ptr = pointers[field]
        if ptr in (0, 0xffffffff) or ptr < SECTION_HEADER.size:
            continue
        start = ptr - SECTION_HEADER.size
        if start in seen or start + SECTION_HEADER.size > len(blob):
            continue
        seen.add(start)
        reserved, sec_id, size = SECTION_HEADER.unpack_from(blob, start)
        entry = {'name': name, 'pointer_field': field, 'data_offset': ptr,
                 'offset': start, 'reserved': reserved, 'section_id': sec_id,
                 'id_name': SECTION_IDS.get(sec_id, '?'), 'size': size}
        if size >= SECTION_HEADER.size + 4 and start + size <= len(blob):
            entry['stored_crc'] = struct.unpack_from('<I', blob, start + size - 4)[0]
            entry['computed_crc'] = section_crc(blob, start, size)
            entry['crc_ok'] = entry['stored_crc'] == entry['computed_crc']
        else:
            entry['truncated'] = True
        out.append(entry)
    out.sort(key=lambda e: e['offset'])
    return pointers, out


def decode_ids(blob, offset, size):
    end = offset + size - 4
    data = blob[offset + SECTION_HEADER.size:end]
    if len(data) < IDS_SECTION.size:
        return None
    values = IDS_SECTION.unpack_from(data, 0)
    ids = dict(zip(IDS_FIELDS, values))
    ids['mac_address'] = ':'.join('%02x' % b for b in ids['mac_address'])
    ids['ssid'] = ids['ssid'].split(b'\x00', 1)[0].decode('ascii', 'replace')
    ids['board_type'] = '0x%08x' % ids['board_type']
    return ids


def cmd_image_info(args):
    with open(args.image, 'rb') as fh:
        blob = fh.read()
    pointers, sections = walk_sections(blob)

    print('image    : %s' % args.image)
    print('size     : %d bytes' % len(blob))
    print('signature: 0x%08x%s' % (pointers['signature'],
          '' if pointers['signature'] == 0x40 else '  (expected 0x40)'))
    print('ptr ver  : 0x%08x' % pointers['pointer_section_version'])
    print()
    print('pointer table:')
    for field in POINTER_FIELDS:
        value = pointers[field]
        if value:
            print('  %-26s 0x%08x' % (field, value))
    print()
    if not sections:
        print('no sections reachable from the pointer table')
        return 1
    print('sections:')
    for sec in sections:
        line = ('  @0x%06x %-16s id=%-2d(%-15s) size=%-7d'
                % (sec['offset'], sec['name'], sec['section_id'],
                   sec['id_name'], sec['size']))
        if sec.get('truncated'):
            line += ' TRUNCATED'
        else:
            line += ('  crc=0x%08x %s' % (sec['stored_crc'],
                     'OK' if sec['crc_ok']
                     else 'MISMATCH (computed 0x%08x)' % sec['computed_crc']))
        print(line)
        if sec['name'] in ('image_info', 'usb_info') and not sec.get('truncated'):
            for tag_name, tag_id, fields in parse_tags(blob, sec['offset'],
                                                       sec['size']):
                if tag_name == 'end':
                    continue
                detail = ', '.join('%s=%s' % kv for kv in fields.items())
                print('        tag %-18s (0x%02x) %s' % (tag_name, tag_id, detail))
        if sec['name'] == 'ids' and not sec.get('truncated'):
            ids = decode_ids(blob, sec['offset'], sec['size'])
            if ids:
                for key in ('version', 'mac_address', 'ssid', 'ppm',
                            'board_type', 'bl_ver'):
                    print('        %-14s %s' % (key, ids[key]))
    bad = [s for s in sections if not s.get('truncated') and not s['crc_ok']]
    return 1 if bad else 0


def cmd_image_fixcrc(args):
    with open(args.image, 'rb') as fh:
        blob = bytearray(fh.read())
    _, sections = walk_sections(bytes(blob))

    fixed = 0
    for sec in sections:
        if sec.get('truncated'):
            print('  %-16s TRUNCATED, skipped' % sec['name'])
            continue
        if sec['crc_ok']:
            print('  %-16s crc 0x%08x OK' % (sec['name'], sec['stored_crc']))
            continue
        print('  %-16s crc 0x%08x -> 0x%08x'
              % (sec['name'], sec['stored_crc'], sec['computed_crc']))
        struct.pack_into('<I', blob, sec['offset'] + sec['size'] - 4,
                         sec['computed_crc'])
        fixed += 1

    if not fixed:
        print('nothing to fix')
        return 0
    if args.dry_run:
        print('dry run, nothing written')
        return 0

    out = args.output or args.image
    if out == args.image and not args.no_backup:
        bak = args.image + '.bak'
        if os.path.exists(bak):
            raise IniError('backup already exists: %s' % bak)
        with open(bak, 'wb') as fh:
            with open(args.image, 'rb') as src:
                fh.write(src.read())
        print('backup   : %s' % bak)
    with open(out, 'wb') as fh:
        fh.write(bytes(blob))
    print('fixed %d section(s) -> %s' % (fixed, out))
    return 0


def cmd_image_extract(args):
    with open(args.image, 'rb') as fh:
        blob = fh.read()
    _, sections = walk_sections(blob)
    os.makedirs(args.output, exist_ok=True)
    for sec in sections:
        if sec.get('truncated'):
            continue
        data = blob[sec['offset'] + SECTION_HEADER.size:
                    sec['offset'] + sec['size'] - 4]
        name = os.path.join(args.output, '%s_id%d.bin' % (sec['name'], sec['section_id']))
        with open(name, 'wb') as fh:
            fh.write(data)
        print('%-16s %7d bytes -> %s' % (sec['name'], len(data), name))
    return 0


def ids_to_ini(ids):
    """Render a decoded ids section as a wiburn [ids] ini section."""
    lines = ['[IDS]']
    for key in IDS_INI_KEYS:
        field = IDS_KEY_TO_FIELD.get(key, key)
        value = ids.get(field)
        if value is None:
            continue
        if key == 'mac_address':
            lines.append('%-22s = %s' % (key, value))
        elif key == 'ssid':
            lines.append('%-22s = %s' % (key, value))
        elif key == 'board':
            lines.append('%-22s = %s' % (key, value))
        else:
            lines.append('%-22s = %d' % (key, value))
    return '\n'.join(lines) + '\n'


def ids_from_ini(path):
    """Pack an [ids] ini section into ids_section bytes."""
    sections, _ = parse_ini(path)
    entries = get_section(sections, 'ids')
    if entries is None:
        raise IniError('no [ids] section in %s' % path)
    values = dict(entries)
    packed = []
    for name in IDS_FIELDS:
        key = next((k for k, f in IDS_KEY_TO_FIELD.items() if f == name), name)
        raw = values.get(key)
        if name == 'mac_address':
            mac = (raw or '00:00:00:00:00:00').replace('-', ':').split(':')
            packed.append(bytes(int(b, 16) for b in mac))
        elif name == 'ssid':
            packed.append((raw or '').encode('ascii')[:32].ljust(32, b'\x00'))
        else:
            packed.append(to_int(raw) if raw is not None else 0)
    return IDS_SECTION.pack(*packed)


def set_section_crc(blob, offset, size):
    struct.pack_into('<I', blob, offset + size - 4,
                     section_crc(bytes(blob), offset, size))


# wiburn.h: SUB_SECTOR is 16 pages = 4 KB, and flash_image.cpp advances every
# section with NEXT_PTR(), i.e. rounds up to the next sub-sector.
SUB_SECTOR = 4 * 1024
IDS_OFFSET_NORMAL = 44 * 1024
IDS_OFFSET_REDUCED = 4 * 1024


def align_up(value, unit=SUB_SECTOR):
    return ((value + unit - 1) // unit) * unit


def build_image(parts, size, reduced=False):
    """Lay out sections the way flash_image.cpp does and return the image.

    parts: [(pointer_field, section_name, section_id, data)].  The ids section
    goes to its fixed offset (44 KB, or 4 KB in a reduced image); everything
    else follows the pointer table, each aligned up to a 4 KB sub-sector.
    """
    image = bytearray(b'\xff' * size)
    pointers = dict.fromkeys(POINTER_FIELDS, 0)
    pointers['signature'] = 0x40

    cursor = align_up(POINTERS.size)
    for field, name, sec_id, data in parts:
        total = SECTION_HEADER.size + len(data) + 4
        if name == 'ids':
            offset = IDS_OFFSET_REDUCED if reduced else IDS_OFFSET_NORMAL
        else:
            offset = cursor
            cursor = align_up(offset + total)
        if offset + total > size:
            raise IniError('%s does not fit: needs 0x%x, image is 0x%x'
                           % (name, offset + total, size))
        SECTION_HEADER.pack_into(image, offset, 0, sec_id, total)
        image[offset + SECTION_HEADER.size:
              offset + SECTION_HEADER.size + len(data)] = data
        set_section_crc(image, offset, total)
        pointers[field] = offset + SECTION_HEADER.size

    POINTERS.pack_into(image, 0, *[pointers[f] for f in POINTER_FIELDS])
    return bytes(image)


# --- translation maps ------------------------------------------------------
# [reg_tree], [fw_symbols] and [ucode_symbols] hold four tokens per line:
# path/name, address, start bit, end bit (ini_parser.cpp::init, case 4).
MAP_SECTIONS = ('reg_tree', 'fw_symbols', 'ucode_symbols')


def load_translation_maps(path):
    sections, _ = parse_ini(path)
    maps = {}
    for name, entries in sections:
        if name not in MAP_SECTIONS:
            continue
        table = maps.setdefault(name, {})
        for key, value in entries:
            if not isinstance(value, tuple) or len(value) != 3:
                continue
            address, start, end = value
            try:
                table[key] = (int(address, 0), int(start, 0), int(end, 0))
            except ValueError:
                continue
    return maps


def apply_bits(word, value, start, end):
    """Place value into bits [start:end] of word, leaving the rest alone."""
    width = end - start + 1
    mask = ((1 << width) - 1) << start
    return (word & ~mask & 0xffffffff) | ((value << start) & mask)


def _find_section(blob, wanted):
    _, sections = walk_sections(blob)
    for sec in sections:
        if sec['name'] == wanted and not sec.get('truncated'):
            return sec
    raise IniError('no %s section in the image' % wanted)


def cmd_ids2ini(args):
    with open(args.image, 'rb') as fh:
        blob = fh.read()
    sec = _find_section(blob, 'ids')
    ids = decode_ids(blob, sec['offset'], sec['size'])
    if ids is None:
        raise IniError('ids section too small')
    text = ids_to_ini(ids)
    if args.output:
        with open(args.output, 'w') as fh:
            fh.write(text)
        print('ids -> %s' % args.output)
    else:
        sys.stdout.write(text)
    return 0


def cmd_ini2ids(args):
    with open(args.image, 'rb') as fh:
        blob = bytearray(fh.read())
    sec = _find_section(bytes(blob), 'ids')
    data = ids_from_ini(args.ini)
    room = sec['size'] - SECTION_HEADER.size - 4
    if len(data) > room:
        raise IniError('ids data is %d bytes, section holds %d' % (len(data), room))
    start = sec['offset'] + SECTION_HEADER.size
    blob[start:start + len(data)] = data
    set_section_crc(blob, sec['offset'], sec['size'])
    out = args.output or args.image
    with open(out, 'wb') as fh:
        fh.write(bytes(blob))
    print('ids updated from %s -> %s (crc recomputed)' % (args.ini, out))
    return 0


def cmd_setid(args):
    with open(args.image, 'rb') as fh:
        blob = bytearray(fh.read())
    sec = _find_section(bytes(blob), 'ids')
    field = IDS_KEY_TO_FIELD.get(args.name, args.name)
    if field not in IDS_FIELDS:
        raise IniError('unknown id %r; known: %s'
                       % (args.name, ', '.join(IDS_INI_KEYS)))
    start = sec['offset'] + SECTION_HEADER.size
    current = list(IDS_SECTION.unpack_from(blob, start))
    index = IDS_FIELDS.index(field)
    old = current[index]
    if field == 'mac_address':
        mac = args.value.replace('-', ':').split(':')
        current[index] = bytes(int(b, 16) for b in mac)
        old = ':'.join('%02x' % b for b in old)
        shown = args.value
    elif field == 'ssid':
        current[index] = args.value.encode('ascii')[:32].ljust(32, b'\x00')
        old = old.split(b'\x00', 1)[0].decode('ascii', 'replace')
        shown = args.value
    else:
        current[index] = to_int(args.value)
        shown = current[index]
    IDS_SECTION.pack_into(blob, start, *current)
    set_section_crc(blob, sec['offset'], sec['size'])
    print('%s: %s -> %s' % (args.name, old, shown))
    if args.dry_run:
        print('dry run, nothing written')
        return 0
    out = args.output or args.image
    with open(out, 'wb') as fh:
        fh.write(bytes(blob))
    print('written   : %s (section crc recomputed)' % out)
    return 0


def cmd_imagebuild(args):
    known = {name: field for field, name in SECTION_POINTERS}
    parts = []
    for item in args.section:
        name, _, path = item.partition('=')
        if name not in known:
            raise IniError('unknown section %r; known: %s'
                           % (name, ', '.join(sorted(known))))
        sec_id = next((i for i, n in SECTION_IDS.items() if n == name), None)
        if sec_id is None:
            raise IniError('no section id for %r' % name)
        with open(path, 'rb') as fh:
            parts.append((known[name], name, sec_id, fh.read()))
    image = build_image(parts, args.size, args.reduced)
    with open(args.output, 'wb') as fh:
        fh.write(image)
    print('%d section(s) -> %s (%d bytes)' % (len(parts), args.output, len(image)))
    for field, name, sec_id, data in parts:
        print('  %-16s id=%-2d %7d bytes' % (name, sec_id, len(data)))
    return 0


def cmd_symbols(args):
    maps = load_translation_maps(args.ini)
    if not maps:
        raise IniError('no [reg_tree] / [fw_symbols] / [ucode_symbols] in %s'
                       % args.ini)
    pattern = (args.pattern or '').lower()
    for name, table in maps.items():
        hits = {k: v for k, v in table.items() if pattern in k.lower()}
        print('[%s] %d entr%s%s' % (name, len(hits), 'y' if len(hits) == 1 else 'ies',
                                    '' if not pattern else ' matching %r' % pattern))
        for key, (address, start, end) in sorted(hits.items())[:args.limit]:
            width = end - start + 1
            print('  %-52s 0x%08x [%d:%d] %d bit%s'
                  % (key, address, end, start, width, '' if width == 1 else 's'))
        if len(hits) > args.limit:
            print('  ... %d more' % (len(hits) - args.limit))
    return 0


def cmd_iniinfo(args):
    sections, trailer = parse_ini(args.ini)
    print('file     : %s' % args.ini)
    print('sections : %d' % len(sections))
    for name, entries in sections:
        kinds = 'translation map' if entries and isinstance(entries[0][1], tuple) \
                else 'key/value'
        print('  [%s]  %d entries (%s)' % (name, len(entries), kinds))
        if name == 'production' and entries:
            pairs = [(to_int(k), to_int(v)) for k, v in entries
                     if not isinstance(v, tuple)]
            print('        image size: %d bytes' % (len(pairs) * 8))
            if pairs:
                print('        first: 0x%08X = 0x%08X' % pairs[0])
                print('        last : 0x%08X = 0x%08X' % pairs[-1])
                if TERMINATOR in pairs:
                    print('        terminator pair present at index %d'
                          % pairs.index(TERMINATOR))
    if trailer is not None:
        print('trailer  : 0x%08X' % trailer)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--section', default='production',
                    help='ini section holding the image (default: production)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('iniinfo', help='describe an ini file')
    p.add_argument('ini')
    p.set_defaults(func=cmd_iniinfo)

    p = sub.add_parser('ini2bin', help='ini -> raw board image')
    p.add_argument('ini')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--trailer', help='append this dword after the pairs')
    p.add_argument('--terminator', action='store_true',
                   help='append the 0xffffffff/0xffffffff end-of-table pair')
    p.set_defaults(func=cmd_ini2bin)

    p = sub.add_parser('bin2ini', help='raw board image -> ini')
    p.add_argument('bin')
    p.add_argument('-o', '--output', required=True)
    p.set_defaults(func=cmd_bin2ini)

    p = sub.add_parser('ini2brd', help='ini(s) -> .brd container')
    p.add_argument('ini', nargs='+')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--addr', nargs='*', type=lambda s: int(s, 0),
                   default=[DEFAULT_BRD_ADDR],
                   help='addr field per data record (default: 0x%08x, then 0)'
                        % DEFAULT_BRD_ADDR)
    p.add_argument('--flags', nargs='*', type=lambda s: int(s, 0), default=[],
                   help='record head flags per data record (default: 0)')
    p.add_argument('--comment', default='', help='file header comment (32 bytes)')
    p.add_argument('--terminator', action='store_true',
                   help='append the 0xffffffff/0xffffffff end-of-table pair')
    p.add_argument('--trailer', type=lambda s: int(s, 0),
                   help='append this dword after the pairs of every record')
    p.set_defaults(func=cmd_ini2brd)

    p = sub.add_parser('imageinfo', help='parse a wiburn flash image (-bin)')
    p.add_argument('image')
    p.set_defaults(func=cmd_image_info)

    p = sub.add_parser('imagefixcrc', help='recompute per-section crc32 in a flash image')
    p.add_argument('image')
    p.add_argument('-o', '--output', help='write here instead of in place')
    p.add_argument('--no-backup', action='store_true')
    p.add_argument('-n', '--dry-run', action='store_true')
    p.set_defaults(func=cmd_image_fixcrc)

    p = sub.add_parser('ids2ini', help='ids section of an image -> [IDS] ini')
    p.add_argument('image')
    p.add_argument('-o', '--output')
    p.set_defaults(func=cmd_ids2ini)

    p = sub.add_parser('ini2ids', help='write an [IDS] ini back into an image')
    p.add_argument('image')
    p.add_argument('ini')
    p.add_argument('-o', '--output', help='write here instead of in place')
    p.set_defaults(func=cmd_ini2ids)

    p = sub.add_parser('setid', help='change one id field in an image')
    p.add_argument('image')
    p.add_argument('--name', required=True, help='e.g. ssid, mac_address, board')
    p.add_argument('--value', required=True)
    p.add_argument('-o', '--output')
    p.add_argument('-n', '--dry-run', action='store_true')
    p.set_defaults(func=cmd_setid)

    p = sub.add_parser('imagebuild', help='lay out a flash image from section blobs')
    p.add_argument('section', nargs='+', metavar='NAME=FILE',
                   help='e.g. ids=ids.bin production=prod.bin fw1_code=fw.bin')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--size', type=lambda v: int(v, 0), default=0x40000,
                   help='image size, default 0x40000 (256 KB)')
    p.add_argument('--reduced', action='store_true',
                   help='put ids at 4 KB instead of 44 KB')
    p.set_defaults(func=cmd_imagebuild)

    p = sub.add_parser('symbols', help='read [reg_tree]/[fw_symbols]/[ucode_symbols]')
    p.add_argument('ini')
    p.add_argument('pattern', nargs='?')
    p.add_argument('--limit', type=int, default=20)
    p.set_defaults(func=cmd_symbols)

    p = sub.add_parser('imageextract', help='dump every section of a flash image')
    p.add_argument('image')
    p.add_argument('-o', '--output', required=True)
    p.set_defaults(func=cmd_image_extract)

    p = sub.add_parser('brd2ini', help='.brd container -> ini(s)')
    p.add_argument('brd')
    p.add_argument('-o', '--output', help='output base name')
    p.set_defaults(func=cmd_brd2ini)

    args = ap.parse_args()
    try:
        return args.func(args)
    except (IniError, wil_brd.BadImage) as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
