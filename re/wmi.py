#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WMI codec for wil6210 / Talyn, driven by the vendor's wmi.xml.

wmi.xml ships in the WIGIG.TLN release and describes the whole interface:
command and event ids, 276 structures with 1165 typed members, 97 enums and
the FW/Linux/Windows type map.  Nothing here is hand-transcribed -- the
layouts come from that file, so they follow the firmware, not a header that
may lag behind it.

Wire format is packed little-endian, matching __packed structs in the driver.
A command sent through debugfs is wmi_cmd_hdr followed by the payload:

    struct wmi_cmd_hdr { u8 mid; u8 reserved; __le16 command_id; __le32 ts; }

so `build()` produces exactly what `cat file > .../wil6210/wmi_send` wants.
"""

import argparse
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict

# fwType -> (struct code, size).  From the TypeConversions table in wmi.xml.
SCALARS = {
    'U08': ('<B', 1), 'S08': ('<b', 1),
    'U16': ('<H', 2), 'S16': ('<h', 2),
    'U32': ('<I', 4), 'S32': ('<i', 4),
    'U64': ('<Q', 8), 'U64_u': ('<Q', 8), 'S64': ('<q', 8),
}

CMD_HDR = struct.Struct('<BBHI')   # mid, reserved, command_id, fw_timestamp

DEFAULT_XML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', 'WIGIG_TLN_7.5_11ad_pack', 'wmi', 'wmi.xml')


class WmiError(Exception):
    pass


class Wmi:
    VIEWS = {'fw': 'publishFW', 'linux': 'publishLinux', 'win': 'publishWin'}

    def __init__(self, path=None, view='fw'):
        if view not in self.VIEWS:
            raise WmiError('view must be one of: %s' % ', '.join(self.VIEWS))
        self.view = view
        self._flag = self.VIEWS[view]
        self.path = path or DEFAULT_XML
        if not os.path.exists(self.path):
            raise WmiError('wmi.xml not found: %s' % self.path)
        root = ET.parse(self.path).getroot()

        self.defines = {}
        for node in root.iter('Define'):
            value = (node.get('value') or '').strip()
            try:
                self.defines[node.get('name')] = int(value.strip('()'), 0)
            except ValueError:
                pass

        self.enums = {}
        for node in root.iter('Enum'):
            values = OrderedDict()
            for item in node.iter('EnumValue'):
                try:
                    values[item.get('name')] = int(item.get('value'), 0)
                except (TypeError, ValueError):
                    continue
            self.enums[node.get('name')] = values

        self.commands = self.enums.get('WMI_COMMAND_ID', {})
        self.events = self.enums.get('WMI_EVENT_ID', {})

        # value -> symbol, per enum, for turning decoded numbers back into names
        self.enum_symbols = {name: {v: k for k, v in values.items()}
                             for name, values in self.enums.items()}
        self._enum_re = re.compile(
            r'\b(' + '|'.join(re.escape(n) for n in sorted(self.enums, key=len,
                                                           reverse=True)) + r')\b')

        # 49 names carry both a 'cmd' and an 'event' structure (CONNECT,
        # RADAR_GENERAL_CONFIG, ...), so the kind is part of the key.
        self.structs = OrderedDict()
        self.kinds = OrderedDict()
        for node in root.iter('Struct'):
            name, kind = node.get('name'), node.get('type') or 'reg'
            self.structs[(kind, name)] = node
            self.kinds.setdefault(name, []).append(kind)

        # struct -> command/event id, taken from the id named in the comment
        self.struct_id = {}
        for key, node in self.structs.items():
            comment = (node.get('comment') or '').strip()
            for token in comment.replace('\\n', ' ').split():
                token = token.strip('\\n,;*')
                if token in self.commands or token in self.events:
                    self.struct_id[key] = token
                    break

    @staticmethod
    def _clean(text):
        return ' '.join((text or '').replace('\\n', ' ').split())

    def doc(self, name, kind=None):
        """Description of a structure, from its comment in wmi.xml.

        Comments usually restate the id first ('WMI_X_CMD - Force ...'); that
        prefix is dropped, since the id is shown separately.
        """
        text = self._clean(self.structs[self.resolve(name, kind)].get('comment'))
        text = text.lstrip('\\/ ')
        text = re.sub(r'^WMI_[A-Z0-9_]+(_CMDID|_EVENTID|_CMD|_EVENT)?\s*[-:]?\s*',
                      '', text)
        return text.strip()

    def member_doc(self, member):
        """Description of one field."""
        return self._clean(member.get('comment'))

    def member_enum(self, member):
        """Enum a field's values belong to, when its comment names one."""
        found = self._enum_re.search(member.get('comment') or '')
        return found.group(1) if found else None

    def symbol(self, enum_name, value):
        """Symbolic name of a value inside an enum, if it has one."""
        return self.enum_symbols.get(enum_name, {}).get(value)

    def resolve(self, name, kind=None):
        """Map a structure name (optionally 'kind:name') to its key."""
        if ':' in name:
            # 'cmd:CONNECT' selects a variant; 'START_SCAN::$_9' is an
            # anonymous nested type whose own name contains colons.
            head, rest = name.split(':', 1)
            if head in self.structs.__class__() or head in ('cmd', 'event', 'reg', 'header'):
                if rest:
                    kind, name = head, rest
        kinds = self.kinds.get(name)
        if not kinds:
            raise WmiError('unknown structure %r' % name)
        if kind:
            if kind not in kinds:
                raise WmiError('%s has no %r variant (has: %s)'
                               % (name, kind, ', '.join(kinds)))
            return (kind, name)
        for preferred in ('cmd', 'event', 'reg', 'header'):
            if preferred in kinds:
                return (preferred, name)
        return (kinds[0], name)

    # -------------------------------------------------------------- layout

    def _count(self, member):
        size = member.get('size') or '1'
        try:
            return int(size, 0)
        except ValueError:
            if size in self.defines:
                return self.defines[size]
            raise WmiError('cannot resolve array size %r of member %r'
                           % (size, member.get('name')))

    def _members(self, name, kind=None):
        """Members visible in the selected view.

        wmi.xml marks every member with publishFW / publishLinux / publishWin:
        the same structure is laid out differently for the firmware and for a
        host header.  PMC, for one, carries mem_base_l+mem_base_h for the
        firmware and a single 64-bit mem_base for Linux.  Payloads sent to the
        device must follow the firmware view, which is the default here.
        """
        node = self.structs[self.resolve(name, kind)]
        return [m for m in node.findall('Member')
                if m.get(self._flag) == 'True']

    def sizeof(self, name, kind=None):
        return sum(self._member_size(m) for m in self._members(name, kind))

    def _member_size(self, member):
        kind = member.get('type')
        count = self._count(member)
        if kind in SCALARS:
            return SCALARS[kind][1] * count
        if kind in self.kinds:
            return self.sizeof(kind) * count
        raise WmiError('unknown member type %r' % kind)

    def layout(self, name, kind=None):
        """[{offset, size, name, type, count, enum, doc}, ...]"""
        out = []
        offset = 0
        for member in self._members(name, kind):
            size = self._member_size(member)
            out.append({'offset': offset, 'size': size,
                        'name': member.get('name'), 'type': member.get('type'),
                        'count': self._count(member),
                        'enum': self.member_enum(member),
                        'doc': self.member_doc(member)})
            offset += size
        return out

    def describe(self, name, data, kind=None):
        """Decode and annotate: value plus what it means.

        Each field becomes {'value', 'symbol', 'enum', 'doc'} where 'symbol' is
        the enum constant matching the number, when the field's comment names
        an enum that has one.
        """
        raw = self.decode(name, data, kind)
        out = OrderedDict()
        for member in self._members(name, kind):
            field = member.get('name')
            value = raw[field]
            enum_name = self.member_enum(member)
            symbol = None
            if enum_name is not None and isinstance(value, int):
                symbol = self.symbol(enum_name, value)
            out[field] = {'value': value, 'symbol': symbol,
                          'enum': enum_name, 'doc': self.member_doc(member)}
        return out

    # -------------------------------------------------------------- encode

    def encode(self, name, values=None, kind=None, **kwargs):
        values = dict(values or {})
        values.update(kwargs)
        unknown = set(values) - {m.get('name') for m in self._members(name, kind)}
        if unknown:
            raise WmiError('%s has no member(s): %s'
                           % (name, ', '.join(sorted(unknown))))

        out = bytearray()
        for member in self._members(name, kind):
            out += self._encode_member(member, values.get(member.get('name')))
        return bytes(out)

    def _encode_member(self, member, value):
        kind = member.get('type')
        count = self._count(member)
        size = self._member_size(member)

        if value is None:
            return b'\x00' * size

        if kind in SCALARS:
            code, width = SCALARS[kind]
            if count == 1 and not isinstance(value, (list, tuple, bytes, bytearray)):
                return struct.pack(code, self._scalar(value, width, member))
            if isinstance(value, (bytes, bytearray)):
                if len(value) > size:
                    raise WmiError('%s: %d bytes do not fit in %d'
                                   % (member.get('name'), len(value), size))
                return bytes(value).ljust(size, b'\x00')
            if isinstance(value, str):
                data = value.encode('utf-8')
                return data.ljust(size, b'\x00')[:size]
            items = list(value)
            if len(items) > count:
                raise WmiError('%s: %d items, room for %d'
                               % (member.get('name'), len(items), count))
            items += [0] * (count - len(items))
            return b''.join(struct.pack(code, self._scalar(v, width, member))
                            for v in items)

        # nested structure, one or an array of them
        if count == 1 and isinstance(value, dict):
            return self.encode(kind, value)
        items = list(value)
        if len(items) > count:
            raise WmiError('%s: %d items, room for %d'
                           % (member.get('name'), len(items), count))
        blob = b''.join(self.encode(kind, item) for item in items)
        return blob.ljust(size, b'\x00')

    def _scalar(self, value, width, member):
        if isinstance(value, str):
            # accept an enum constant by name, preferring the field's own enum
            own = self.member_enum(member)
            if own and value in self.enums.get(own, {}):
                value = self.enums[own][value]
            else:
                for values in self.enums.values():
                    if value in values:
                        value = values[value]
                        break
                else:
                    value = int(value, 0)
        limit = 1 << (8 * width)
        if not -limit // 2 <= value < limit:
            raise WmiError('%s: value %d does not fit in %d byte(s)'
                           % (member.get('name'), value, width))
        return value

    def build(self, name, values=None, mid=0, timestamp=0, cmd_id=None, **kwargs):
        """Full wmi_cmd_hdr + payload, ready to write to debugfs/wmi_send.

        A handful of structures are not named after their command id; pass
        cmd_id explicitly for those.
        """
        if cmd_id is None:
            cmd_id = self.command_id(name)
        payload = self.encode(name, values, kind='cmd', **kwargs)
        return CMD_HDR.pack(mid & 0xff, 0, cmd_id & 0xffff,
                            timestamp & 0xffffffff) + payload

    def command_id(self, name):
        token = self.struct_id.get(self.resolve(name, 'cmd'))
        if token and token in self.commands:
            return self.commands[token]
        guess = 'WMI_%s_CMDID' % name.upper()
        if guess in self.commands:
            return self.commands[guess]
        if name in self.commands:
            return self.commands[name]
        raise WmiError('no command id for %r' % name)

    # -------------------------------------------------------------- decode

    def decode(self, name, data, kind=None):
        out = OrderedDict()
        offset = 0
        for member in self._members(name, kind):
            size = self._member_size(member)
            chunk = data[offset:offset + size]
            if len(chunk) < size:
                raise WmiError('%s: truncated at member %r (need %d, have %d)'
                               % (name, member.get('name'), size, len(chunk)))
            out[member.get('name')] = self._decode_member(member, chunk)
            offset += size
        return out

    def _decode_member(self, member, chunk):
        kind = member.get('type')
        count = self._count(member)
        if kind in SCALARS:
            code, width = SCALARS[kind]
            values = [struct.unpack_from(code, chunk, i * width)[0]
                      for i in range(count)]
            return values[0] if count == 1 else values
        unit = self.sizeof(kind)
        items = [self.decode(kind, chunk[i * unit:(i + 1) * unit])
                 for i in range(count)]
        return items[0] if count == 1 else items

    def decode_event(self, data):
        """Split a captured event into (id name, header, decoded payload)."""
        if len(data) < CMD_HDR.size:
            raise WmiError('too short for a wmi header')
        mid, _, event_id, timestamp = CMD_HDR.unpack_from(data, 0)
        name = next((n for n, v in self.events.items() if v == event_id), None)
        key = next((k for k, t in self.struct_id.items()
                    if t == name and k[0] == 'event'), None)
        if key is None and name:
            # fall back to the naming convention: WMI_<X>_EVENTID -> struct <X>
            guess = name[4:-8] if name.startswith('WMI_') and \
                name.endswith('_EVENTID') else None
            if guess and ('event', guess) in self.structs:
                key = ('event', guess)
        struct_name = key[1] if key else None
        payload = data[CMD_HDR.size:]
        decoded = self.decode(struct_name, payload, 'event') if key else None
        return {'mid': mid, 'id': event_id, 'event': name,
                'struct': struct_name, 'timestamp': timestamp,
                'payload': decoded if decoded is not None else payload.hex()}


# ---------------------------------------------------------------- commands

def cmd_list(args):
    wmi = Wmi(args.xml, args.view)
    pattern = (args.pattern or '').upper()
    rows = []
    for (kind_of, name) in wmi.structs:
        token = wmi.struct_id.get((kind_of, name), '')
        if pattern and pattern not in name.upper() and pattern not in token.upper():
            continue
        kind = kind_of
        ident = ''
        if token in wmi.commands:
            ident = '0x%04x' % wmi.commands[token]
        elif token in wmi.events:
            ident = '0x%04x' % wmi.events[token]
        try:
            size = wmi.sizeof(name, kind_of)
        except WmiError:
            size = -1
        rows.append((name, kind, ident, size, wmi.doc(name, kind_of)))
    for name, kind, ident, size, doc in rows:
        print('%-40s %-5s %-7s %5s  %s'
              % (name, kind, ident, size if size >= 0 else '?',
                 (doc[:70] + '...') if len(doc) > 73 else doc))
    print('\n%d structure(s)' % len(rows))
    return 0


def cmd_show(args):
    wmi = Wmi(args.xml, args.view)
    key = wmi.resolve(args.name, args.kind)
    name = key[1]
    token = wmi.struct_id.get(key, '')
    print('structure : %s (%s)' % (name, key[0]))
    if len(wmi.kinds[name]) > 1:
        print('variants  : %s' % ', '.join(wmi.kinds[name]))
    if token:
        table = wmi.commands if token in wmi.commands else wmi.events
        print('id        : %s = 0x%04x' % (token, table[token]))
    print('size      : %d bytes' % wmi.sizeof(name, key[0]))
    doc = wmi.doc(name, key[0])
    if doc:
        print('purpose   : %s' % doc)
    print()
    print('  %-5s %-5s %-28s %-20s %s' % ('off', 'size', 'field', 'type', 'count'))
    for item in wmi.layout(name, key[0]):
        print('  %-5d %-5d %-28s %-20s %s'
              % (item['offset'], item['size'], item['name'], item['type'],
                 item['count']))
        if item['enum']:
            values = wmi.enums.get(item['enum'], {})
            shown = ', '.join('%s=%d' % (k, v) for k, v in list(values.items())[:4])
            more = ' ...' if len(values) > 4 else ''
            print('        enum %s: %s%s' % (item['enum'], shown, more))
        doc_text = item['doc']
        if doc_text and doc_text != 'enum %s' % (item['enum'] or ''):
            print('        %s' % doc_text)
    return 0


def cmd_build(args):
    wmi = Wmi(args.xml, args.view)
    values = {}
    for item in args.field:
        key, _, value = item.partition('=')
        if ',' in value:
            values[key] = [int(v, 0) for v in value.split(',') if v != '']
        else:
            try:
                values[key] = int(value, 0)
            except ValueError:
                values[key] = value
    blob = wmi.build(args.name, values, mid=args.mid, cmd_id=args.cmd_id)
    if args.output:
        with open(args.output, 'wb') as fh:
            fh.write(blob)
        print('%s -> %s (%d bytes: %d header + %d payload)'
              % (args.name, args.output, len(blob), CMD_HDR.size,
                 len(blob) - CMD_HDR.size))
        print('send with:  cat %s > $(find /sys/kernel/debug/ieee80211 '
              '-name wil6210)/wmi_send' % args.output)
    else:
        print(blob.hex())
    return 0


def cmd_decode(args):
    wmi = Wmi(args.xml, args.view)
    with open(args.file, 'rb') as fh:
        data = fh.read()
    if args.name:
        _print_fields(wmi, wmi.describe(args.name, data, args.kind))
    else:
        info = wmi.decode_event(data)
        print('event     : %s (0x%04x)' % (info['event'], info['id']))
        print('structure : %s' % info['struct'])
        print('mid       : %d' % info['mid'])
        if info['struct']:
            doc = wmi.doc(info['struct'], 'event')
            if doc:
                print('purpose   : %s' % doc)
            print()
            _print_fields(wmi, wmi.describe(info['struct'],
                                            data[CMD_HDR.size:], 'event'))
        else:
            print('  raw: %s' % info['payload'])
    return 0


def _print_fields(wmi, fields):
    for name, item in fields.items():
        value = item['value']
        line = '  %-26s %s' % (name, value)
        if item['symbol']:
            line += '  = %s' % item['symbol']
        elif item['enum']:
            line += '  (%s: no symbol for this value)' % item['enum']
        print(line)
        doc_text = item['doc']
        if doc_text and doc_text != 'enum %s' % (item['enum'] or ''):
            print('  %-26s %s' % ('', doc_text))


def cmd_enum(args):
    wmi = Wmi(args.xml, args.view)
    pattern = (args.pattern or '').upper()
    for name, values in wmi.enums.items():
        if pattern and pattern not in name.upper():
            continue
        print('%s (%d values)' % (name, len(values)))
        for key, value in values.items():
            print('    %-46s 0x%x' % (key, value))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--xml', help='path to wmi.xml (default: the 11ad pack)')
    ap.add_argument('--view', default='fw', choices=('fw', 'linux', 'win'),
                    help='which publish flag selects members (default: fw, '
                         'the layout the device itself expects)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('list', help='list structures, ids and sizes')
    p.add_argument('pattern', nargs='?')
    p.set_defaults(func=cmd_list)

    p = sub.add_parser('show', help='field layout of one structure')
    p.add_argument('name')
    p.add_argument('--kind', choices=('cmd', 'event', 'reg', 'header'),
                   help='pick a variant when a name has both')
    p.set_defaults(func=cmd_show)

    p = sub.add_parser('build', help='build a command blob for wmi_send')
    p.add_argument('name')
    p.add_argument('field', nargs='*', help='field=value (lists as a,b,c)')
    p.add_argument('-o', '--output')
    p.add_argument('--mid', type=int, default=0)
    p.add_argument('--id', dest='cmd_id', type=lambda v: int(v, 0),
                   help='command id, for structures not named after one')
    p.set_defaults(func=cmd_build)

    p = sub.add_parser('decode', help='decode a captured blob')
    p.add_argument('file')
    p.add_argument('--name', help='structure name; omit to read the wmi header')
    p.add_argument('--kind', choices=('cmd', 'event', 'reg', 'header'))
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser('enum', help='dump enums')
    p.add_argument('pattern', nargs='?')
    p.set_defaults(func=cmd_enum)

    args = ap.parse_args()
    try:
        return args.func(args)
    except WmiError as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
