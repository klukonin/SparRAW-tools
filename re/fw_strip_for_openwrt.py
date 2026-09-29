#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Strip a MikroTik wil6210 .fw down to the records the mainline/OpenWrt
Linux driver (wil_fw.c) understands, and recompute a valid CRC.

MikroTik's decrypted wil6210 firmware carries extra trailing records
    type 100 (0x64)  ucode log-string table
    type 101 (0x65)  fw    log-string table
    type 102 (0x66)  trailer
The mainline driver's fw_handle_record() only knows record types 1,2,3,5,6,7,
8,9 and returns -EINVAL on any unknown type, so loading the MikroTik image as
is would fail. The three string tables are never loaded into device memory
(the fw only stashes a string *pointer* in the trace ring for the HOST to
resolve), so dropping them is safe for on-device operation; trace decoding on
OpenWrt uses the separate fw-string mechanism instead.

Usage:  fw_strip_for_openwrt.py IN.fw -o OUT.fw
Round-trips through wil_brd unpack/pack, which recomputes data_len + crc.
"""
import argparse, json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
DROP = {100, 101, 102}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('infile')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--keep-comments', action='store_true',
                    help='keep type-1 comment records (default: keep)')
    args = ap.parse_args()
    wil_brd = os.path.join(HERE, 'wil_brd.py')
    with tempfile.TemporaryDirectory() as wd:
        subprocess.run([sys.executable, wil_brd, 'unpack', args.infile, '-o', wd],
                       check=True)
        mpath = os.path.join(wd, 'manifest.json')
        m = json.load(open(mpath))
        before = len(m['records'])
        m['records'] = [r for r in m['records'] if r['type'] not in DROP]
        for i, r in enumerate(m['records']):
            r['index'] = i
        json.dump(m, open(mpath, 'w'), indent=1)
        subprocess.run([sys.executable, wil_brd, 'pack', mpath, '-o', args.out],
                       check=True)
        print('stripped %d -> %d records; kept types %s'
              % (before, len(m['records']), [r['type'] for r in m['records']]))
    subprocess.run([sys.executable, wil_brd, 'info', args.out])

if __name__ == '__main__':
    main()
