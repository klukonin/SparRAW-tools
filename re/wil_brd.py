#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pack/unpack wil6210 board (.brd) and firmware (.fw) container files.

Both file types use the same record container described by the driver's
fw.h / fw_inc.c:

    struct wil_fw_record_head { __le16 type; __le16 flags; __le32 size; }

The first record is always a file header (type 6) carrying the '0126'
signature, a crc32 over the whole image and the total data length.

unpack writes every record payload to a separate file plus a manifest.json;
pack rebuilds the image from that manifest, recomputing data_len and crc.
The round trip is byte exact.

Note on .brd files: the addr field of each data record is ignored by the
driver.  Real destination addresses come from the brd_info table stored in
a comment record of the matching .fw file -- use `brdinfo` on the .fw and
pass the result to `info`/`unpack` via --fw to get them annotated.
"""

import argparse
import json
import os
import struct
import sys
import zlib

SIGNATURE = 0x36323130  # '0126'
FMT_VERSION = 1

HEAD = struct.Struct('<HHI')
FILE_HEADER = struct.Struct('<IIIII32s')

# enum wil_fw_record_type
TYPES = {
    1: 'comment',
    2: 'data',
    3: 'fill',
    4: 'action',
    5: 'verify',
    6: 'file_header',
    7: 'direct_write',
    8: 'gateway_data',
    9: 'gateway_data4',
}

CAPABILITIES_MAGIC = 0xabcddcba
CONCURRENCY_MAGIC = 0xfedccdef
BRD_FILE_MAGIC = 0xabcddcbb


class BadImage(Exception):
    pass


def u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


# ---------------------------------------------------------------- decoding

def decode_comment(payload):
    """Decode the known comment sub-types, keyed by a leading magic."""
    out = {}
    if len(payload) >= 4:
        magic = u32(payload, 0)
        out['magic'] = '0x%08x' % magic
        if magic == CAPABILITIES_MAGIC:
            out['kind'] = 'capabilities'
            out['capabilities'] = payload[4:].hex()
            return out
        if magic == CONCURRENCY_MAGIC and len(payload) >= 8:
            version, n_mids, n_combos = struct.unpack_from('<IBBH', payload, 0)[1:]
            out['kind'] = 'concurrency'
            out['version'] = version
            out['n_mids'] = n_mids
            out['n_combos'] = n_combos
            combos = []
            off = 8
            for _ in range(n_combos):
                if off + 4 > len(payload):
                    break
                n_limits, max_if, n_chan, same_bi = struct.unpack_from('<BBBB', payload, off)
                off += 4
                limits = []
                for _ in range(n_limits):
                    if off + 4 > len(payload):
                        break
                    mx, types = struct.unpack_from('<HH', payload, off)
                    off += 4
                    limits.append({'max': mx, 'types': '0x%04x' % types})
                combos.append({'max_interfaces': max_if,
                               'n_diff_channels': n_chan,
                               'same_bi': same_bi,
                               'limits': limits})
            out['combos'] = combos
            return out
        if magic == BRD_FILE_MAGIC and len(payload) >= 8:
            out['kind'] = 'brd_file'
            out['version'] = u32(payload, 4)
            entries = []
            off = 8
            while off + 8 <= len(payload):
                base, max_size = struct.unpack_from('<II', payload, off)
                entries.append({'base_addr': '0x%08x' % base,
                                'max_size_bytes': max_size})
                off += 8
            out['brd_info'] = entries
            return out

    text = payload.split(b'\x00', 1)[0]
    try:
        text = text.decode('ascii')
    except UnicodeDecodeError:
        text = ''
    if text.isprintable() and text:
        out['kind'] = 'text'
        out['text'] = text
        return out

    if 'magic' in out:
        # Vendor comment records the upstream driver ignores (seen in Talyn
        # firmware: 0xabcddcbc, 0xabcddcbd, 0x0abcddce, 0x0abcddcf).
        out['kind'] = 'unknown'
        out['dwords'] = ['0x%08x' % u32(payload, off)
                         for off in range(4, len(payload) - 3, 4)]
    return out


def decode_record(rtype, payload):
    """Informational decoding; never used when repacking."""
    if rtype == 1:
        return decode_comment(payload)
    if rtype == 2 and len(payload) >= 4:
        return {'addr': '0x%08x' % u32(payload, 0),
                'data_bytes': len(payload) - 4}
    if rtype == 3 and len(payload) >= 12:
        addr, value, size = struct.unpack_from('<III', payload, 0)
        return {'addr': '0x%08x' % addr, 'value': '0x%08x' % value, 'size': size}
    if rtype == 4 and len(payload) >= 4:
        return {'action': '0x%08x' % u32(payload, 0),
                'data_bytes': len(payload) - 4}
    if rtype == 5 and len(payload) >= 12:
        addr, value, mask = struct.unpack_from('<III', payload, 0)
        return {'addr': '0x%08x' % addr, 'value': '0x%08x' % value,
                'mask': '0x%08x' % mask}
    if rtype == 6 and len(payload) >= FILE_HEADER.size:
        sig, reserved, crc, version, data_len, comment = FILE_HEADER.unpack_from(payload, 0)
        return {'signature': '0x%08x' % sig,
                'reserved': reserved,
                'crc': '0x%08x' % crc,
                'version': version,
                'data_len': data_len,
                'comment': comment.split(b'\x00', 1)[0].decode('ascii', 'replace')}
    if rtype == 7:
        return {'n_writes': len(payload) // 12}
    if rtype == 8 and len(payload) >= 20:
        return {'gateway_addr_addr': '0x%08x' % u32(payload, 0),
                'gateway_value_addr': '0x%08x' % u32(payload, 4),
                'gateway_cmd_addr': '0x%08x' % u32(payload, 8),
                'gateway_ctrl_address': '0x%08x' % u32(payload, 12),
                'command': '0x%08x' % u32(payload, 16),
                'n_writes': (len(payload) - 20) // 8}
    if rtype == 9 and len(payload) >= 32:
        return {'gateway_addr_addr': '0x%08x' % u32(payload, 0),
                'gateway_cmd_addr': '0x%08x' % u32(payload, 20),
                'gateway_ctrl_address': '0x%08x' % u32(payload, 24),
                'command': '0x%08x' % u32(payload, 28),
                'n_writes': (len(payload) - 32) // 20}
    return {}


# ---------------------------------------------------------------- parsing

def parse_header(blob):
    if len(blob) < HEAD.size + FILE_HEADER.size:
        raise BadImage('file too short: %d bytes' % len(blob))
    rtype, flags, size = HEAD.unpack_from(blob, 0)
    if rtype != 6:
        raise BadImage('first record is type %d, expected file_header(6)' % rtype)
    sig, reserved, crc, version, data_len, comment = FILE_HEADER.unpack_from(blob, HEAD.size)
    if sig != SIGNATURE:
        raise BadImage('bad signature 0x%08x, expected 0x%08x' % (sig, SIGNATURE))
    if version > FMT_VERSION:
        raise BadImage('unsupported format version %d' % version)
    if data_len % 4:
        raise BadImage('data_len not 4-aligned: %d' % data_len)
    if data_len < HEAD.size + FILE_HEADER.size:
        raise BadImage('data_len too small: %d' % data_len)
    if len(blob) < data_len:
        raise BadImage('file truncated at %d/%d' % (len(blob), data_len))
    return {'head_flags': flags, 'head_size': size, 'signature': sig,
            'reserved': reserved, 'crc': crc, 'version': version,
            'data_len': data_len, 'comment': comment}


def compute_crc(blob, data_len):
    """~crc32(~0, image) with the crc field zeroed -- i.e. plain zlib crc32."""
    patched = bytearray(blob[:data_len])
    crc_off = HEAD.size + 8  # signature + reserved
    struct.pack_into('<I', patched, crc_off, 0)
    return zlib.crc32(bytes(patched)) & 0xffffffff


def parse_records(blob, data_len):
    records = []
    off = 0
    while off < data_len:
        if data_len - off < HEAD.size:
            raise BadImage('trailing %d bytes at offset %d, too short for a '
                           'record head' % (data_len - off, off))
        rtype, flags, size = HEAD.unpack_from(blob, off)
        end = off + HEAD.size + size
        if end > data_len:
            raise BadImage('record %d at offset %d overruns data_len '
                           '(%d > %d)' % (len(records), off, end, data_len))
        payload = blob[off + HEAD.size:end]
        records.append({'index': len(records), 'offset': off, 'type': rtype,
                        'type_name': TYPES.get(rtype, 'unknown'),
                        'flags': flags, 'size': size, 'payload': payload})
        off = end
    return records


def load(path):
    with open(path, 'rb') as fh:
        blob = fh.read()
    if len(blob) % 4:
        raise BadImage('image size not 4-aligned: %d' % len(blob))
    hdr = parse_header(blob)
    data_len = hdr['data_len']
    hdr['crc_computed'] = compute_crc(blob, data_len)
    hdr['crc_ok'] = hdr['crc_computed'] == hdr['crc']
    records = parse_records(blob, data_len)
    return blob, hdr, records


def read_brd_info(fw_path):
    """Pull the brd_info table out of a .fw file's comment record."""
    _, _, records = load(fw_path)
    for rec in records:
        if rec['type'] != 1:
            continue
        info = decode_comment(rec['payload'])
        if info.get('kind') == 'brd_file':
            return info['brd_info']
    return []


# ---------------------------------------------------------------- commands

def cmd_info(args):
    blob, hdr, records = load(args.file)
    brd_info = read_brd_info(args.fw) if args.fw else []

    print('file      : %s' % args.file)
    print('size      : %d bytes' % len(blob))
    print('data_len  : %d bytes%s' % (hdr['data_len'],
          '' if hdr['data_len'] == len(blob)
          else '  (+%d trailing)' % (len(blob) - hdr['data_len'])))
    print('signature : 0x%08x (%r)' % (hdr['signature'],
          struct.pack('<I', hdr['signature']).decode('ascii', 'replace')))
    print('version   : %d' % hdr['version'])
    print('comment   : %r' % hdr['comment'].split(b'\x00', 1)[0].decode('ascii', 'replace'))
    print('crc       : 0x%08x  %s' % (hdr['crc'],
          'OK' if hdr['crc_ok'] else 'MISMATCH (computed 0x%08x)' % hdr['crc_computed']))
    print('records   : %d' % len(records))
    print()

    data_idx = 0
    for rec in records:
        extra = decode_record(rec['type'], rec['payload'])
        line = '  [%3d] @0x%06x %-13s size=%-7d' % (
            rec['index'], rec['offset'], rec['type_name'], rec['size'])
        if rec['flags']:
            line += ' flags=0x%04x' % rec['flags']
        print(line)
        if rec['type'] == 2 and brd_info:
            if data_idx < len(brd_info):
                bi = brd_info[data_idx]
                extra = dict(extra)
                extra['brd_dest_addr'] = bi['base_addr']
                extra['brd_max_size'] = bi['max_size_bytes']
                if bi['max_size_bytes'] and rec['size'] > bi['max_size_bytes']:
                    extra['WARNING'] = 'record exceeds max_size_bytes'
            else:
                extra = dict(extra)
                extra['WARNING'] = 'no brd_info entry for this record'
            data_idx += 1
        for key, value in extra.items():
            print('        %-20s %s' % (key, value))
    if brd_info:
        print()
        print('brd_info from %s:' % args.fw)
        for i, bi in enumerate(brd_info):
            print('  [%d] base_addr=%s max_size_bytes=%d'
                  % (i, bi['base_addr'], bi['max_size_bytes']))
    return 0 if hdr['crc_ok'] else 1


def cmd_unpack(args):
    blob, hdr, records = load(args.file)
    outdir = args.output or (os.path.basename(args.file) + '.unpacked')
    os.makedirs(outdir, exist_ok=True)

    brd_info = read_brd_info(args.fw) if args.fw else []

    manifest = {
        'source': os.path.basename(args.file),
        'size': len(blob),
        'data_len': hdr['data_len'],
        'header': {
            'head_flags': hdr['head_flags'],
            'signature': '0x%08x' % hdr['signature'],
            'reserved': hdr['reserved'],
            'version': hdr['version'],
            'comment': hdr['comment'].hex(),
            'crc_original': '0x%08x' % hdr['crc'],
            'crc_ok': hdr['crc_ok'],
        },
        'brd_info': brd_info,
        'records': [],
    }

    data_idx = 0
    for rec in records:
        entry = {
            'index': rec['index'],
            'type': rec['type'],
            'type_name': rec['type_name'],
            'flags': rec['flags'],
            'size': rec['size'],
            'decoded': decode_record(rec['type'], rec['payload']),
        }
        if rec['type'] == 6:
            # regenerated on pack; payload not written out
            entry['payload'] = None
        else:
            name = 'rec%03d_%s' % (rec['index'], rec['type_name'])
            if rec['type'] == 2:
                name += '_%s' % entry['decoded'].get('addr', '')
                if brd_info and data_idx < len(brd_info):
                    entry['brd_dest_addr'] = brd_info[data_idx]['base_addr']
                data_idx += 1
            name += '.bin'
            with open(os.path.join(outdir, name), 'wb') as fh:
                fh.write(rec['payload'])
            entry['payload'] = name
        manifest['records'].append(entry)

    trailing = blob[hdr['data_len']:]
    if trailing:
        with open(os.path.join(outdir, 'trailing.bin'), 'wb') as fh:
            fh.write(trailing)
        manifest['trailing'] = 'trailing.bin'

    with open(os.path.join(outdir, 'manifest.json'), 'w') as fh:
        json.dump(manifest, fh, indent=2)

    print('unpacked %d records into %s' % (len(records), outdir))
    if not hdr['crc_ok']:
        print('warning: source crc did not verify', file=sys.stderr)
    return 0


def cmd_pack(args):
    path = args.manifest
    if os.path.isdir(path):
        path = os.path.join(path, 'manifest.json')
    indir = os.path.dirname(os.path.abspath(path))
    with open(path) as fh:
        manifest = json.load(fh)

    hdr = manifest['header']
    body = bytearray()
    for entry in manifest['records']:
        if entry['type'] == 6:
            comment = bytes.fromhex(hdr['comment'])
            payload = FILE_HEADER.pack(int(hdr['signature'], 16),
                                       hdr['reserved'], 0, hdr['version'],
                                       0, comment)
        else:
            with open(os.path.join(indir, entry['payload']), 'rb') as fh:
                payload = fh.read()
        if len(payload) % 4:
            raise BadImage('record %d payload not 4-aligned: %d bytes'
                           % (entry['index'], len(payload)))
        body += HEAD.pack(entry['type'], entry['flags'], len(payload))
        body += payload

    # file header layout after the 8-byte record head:
    #   signature(4) reserved(4) crc(4) version(4) data_len(4) comment(32)
    data_len = len(body)
    struct.pack_into('<I', body, HEAD.size + 16, data_len)
    crc = compute_crc(bytes(body), data_len)
    struct.pack_into('<I', body, HEAD.size + 8, crc)

    if manifest.get('trailing'):
        with open(os.path.join(indir, manifest['trailing']), 'rb') as fh:
            body += fh.read()

    out = args.output or manifest['source']
    with open(out, 'wb') as fh:
        fh.write(bytes(body))
    print('packed %d records -> %s (%d bytes, data_len %d, crc 0x%08x)'
          % (len(manifest['records']), out, len(body), data_len, crc))
    return 0


def find_records_end(blob, limit):
    """Walk records from offset 0 while they fit; return end of the last
    complete, well-formed record.  Used to repair a bogus data_len."""
    off = 0
    last_good = 0
    while off + HEAD.size <= limit:
        _, _, size = HEAD.unpack_from(blob, off)
        if size % 4:
            break
        end = off + HEAD.size + size
        if end > limit:
            break
        off = end
        last_good = off
    return last_good


def cmd_fixcrc(args):
    if args.output and len(args.file) > 1:
        raise BadImage('-o works with a single file; use --in-place for several')
    rc = 0
    for i, path in enumerate(args.file):
        if len(args.file) > 1:
            if i:
                print()
            print('== %s' % path)
        try:
            fix_one(path, args)
        except BadImage as exc:
            sys.stdout.flush()
            print('error: %s' % exc, file=sys.stderr)
            sys.stderr.flush()
            rc = 2
    return rc


def fix_one(path, args):
    with open(path, 'rb') as fh:
        blob = bytearray(fh.read())

    usable = len(blob) - (len(blob) % 4)
    if usable != len(blob):
        print('note: file size %d is not 4-aligned, ignoring last %d byte(s)'
              % (len(blob), len(blob) - usable))

    if usable < HEAD.size + FILE_HEADER.size:
        raise BadImage('file too short: %d bytes' % len(blob))
    rtype, _, _ = HEAD.unpack_from(blob, 0)
    if rtype != 6:
        raise BadImage('first record is type %d, expected file_header(6) -- '
                       'not a wil container (encrypted?)' % rtype)
    sig = u32(blob, HEAD.size)
    if sig != SIGNATURE:
        raise BadImage('bad signature 0x%08x, expected 0x%08x (encrypted?)'
                       % (sig, SIGNATURE))

    old_dlen = u32(blob, HEAD.size + 16)
    old_crc = u32(blob, HEAD.size + 8)

    dlen_sane = (old_dlen % 4 == 0 and
                 HEAD.size + FILE_HEADER.size <= old_dlen <= usable and
                 find_records_end(blob, old_dlen) == old_dlen)

    if not dlen_sane and not args.fix_data_len:
        raise BadImage(
            'record structure is broken (stored data_len %d does not match the '
            'record layout) -- only the crc is repaired by default. '
            'Pass --fix-data-len to rewrite data_len from the actual records.'
            % old_dlen)

    new_dlen = old_dlen
    if args.fix_data_len:
        new_dlen = find_records_end(blob, usable)
        if new_dlen < HEAD.size + FILE_HEADER.size:
            raise BadImage('cannot recover data_len: no complete records')

    if new_dlen != old_dlen:
        print('data_len : %d -> %d  (stored value was inconsistent)'
              % (old_dlen, new_dlen))
        struct.pack_into('<I', blob, HEAD.size + 16, new_dlen)
    else:
        print('data_len : %d (unchanged)' % old_dlen)

    new_crc = compute_crc(bytes(blob), new_dlen)
    print('crc      : 0x%08x -> 0x%08x%s' % (old_crc, new_crc,
          '  (already correct)' if old_crc == new_crc else ''))
    struct.pack_into('<I', blob, HEAD.size + 8, new_crc)

    if old_crc == new_crc and new_dlen == old_dlen:
        print('nothing to fix')
        if not args.output:
            return 0

    if args.dry_run:
        print('dry run, nothing written')
        return 0

    if args.output:
        out = args.output
    elif args.in_place:
        out = path
        if not args.no_backup:
            bak = path + '.bak'
            if os.path.exists(bak):
                raise BadImage('backup already exists: %s' % bak)
            with open(bak, 'wb') as fh:
                with open(path, 'rb') as src:
                    fh.write(src.read())
            print('backup   : %s' % bak)
    else:
        raise BadImage('specify -o OUT or --in-place')

    with open(out, 'wb') as fh:
        fh.write(bytes(blob))
    print('written  : %s' % out)
    return 0


def cmd_brdinfo(args):
    entries = read_brd_info(args.fw)
    if not entries:
        print('no brd_file comment record found in %s' % args.fw, file=sys.stderr)
        return 1
    for i, bi in enumerate(entries):
        print('[%d] base_addr=%s max_size_bytes=%d'
              % (i, bi['base_addr'], bi['max_size_bytes']))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('info', help='parse and describe a .brd/.fw file')
    p.add_argument('file')
    p.add_argument('--fw', help='matching .fw file, to resolve brd_info addresses')
    p.set_defaults(func=cmd_info)

    p = sub.add_parser('unpack', help='split records into files + manifest.json')
    p.add_argument('file')
    p.add_argument('-o', '--output', help='output directory')
    p.add_argument('--fw', help='matching .fw file, to annotate brd_info')
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser('pack', help='rebuild an image from manifest.json')
    p.add_argument('manifest', help='manifest.json or the directory holding it')
    p.add_argument('-o', '--output', help='output file')
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser('fixcrc', help='recompute the crc of structurally valid images')
    p.add_argument('file', nargs='+')
    p.add_argument('-o', '--output', help='write the repaired image here')
    p.add_argument('-i', '--in-place', action='store_true',
                   help='overwrite the input file (keeps a .bak copy)')
    p.add_argument('--no-backup', action='store_true',
                   help='with --in-place, do not keep a .bak copy')
    p.add_argument('--fix-data-len', action='store_true',
                   help='also rewrite data_len from the actual record layout '
                        '(done automatically when the stored value is broken)')
    p.add_argument('-n', '--dry-run', action='store_true',
                   help='report what would change, write nothing')
    p.set_defaults(func=cmd_fixcrc)

    p = sub.add_parser('brdinfo', help='print the brd_info table from a .fw')
    p.add_argument('fw')
    p.set_defaults(func=cmd_brdinfo)

    args = ap.parse_args()
    try:
        return args.func(args)
    except BadImage as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
