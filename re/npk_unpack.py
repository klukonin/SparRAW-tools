#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unpack a Mikrotik RouterOS .npk package and extract its squashfs contents.

NPK layout (observed): 4096-byte NPK header (magic 1e f1 d0 ba ...), then an
xz-compressed SquashFS 4.0 image starting at offset 0x1000. Inside the squashfs,
the wil6210 60 GHz firmware and board files live under lib/firmware/ (encrypted),
and the userspace handler that decrypts them is nova/bin/wireless.

Usage:
    npk_unpack.py <package.npk> [-o outdir]      # extract squashfs tree
    npk_unpack.py <package.npk> --list           # list wil6210 fw/brd only
"""
import argparse, os, struct, subprocess, sys

NPK_MAGIC = bytes([0x1e, 0xf1, 0xd0, 0xba])
SQUASHFS_OFFSET = 0x1000            # squashfs starts here in every npk seen

def carve_squashfs(npk):
    data = open(npk, 'rb').read()
    if data[:4] != NPK_MAGIC:
        sys.exit('not an NPK (bad magic %s)' % data[:4].hex())
    sq = data[SQUASHFS_OFFSET:]
    if sq[:4] != b'hsqs':
        # locate squashfs magic if layout differs
        i = data.find(b'hsqs')
        if i < 0:
            sys.exit('no squashfs found')
        sq = data[i:]
    return sq

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('npk')
    ap.add_argument('-o', '--output', default=None)
    ap.add_argument('--list', action='store_true',
                    help='after extraction, list wil6210 fw/brd files')
    args = ap.parse_args()
    out = args.output or (os.path.splitext(os.path.basename(args.npk))[0] + '_root')
    sq = carve_squashfs(args.npk)
    sqfile = out + '.sqfs'
    with open(sqfile, 'wb') as f:
        f.write(sq)
    r = subprocess.run(['unsquashfs', '-f', '-d', out, sqfile],
                       capture_output=True, text=True)
    print(r.stdout.strip().splitlines()[-1] if r.stdout else 'unsquashfs done',
          'rc=%d' % r.returncode)
    fw = []
    for dp, _, fns in os.walk(out):
        for fn in fns:
            if 'wil6210' in fn or 'wil6436' in fn:
                fw.append(os.path.join(dp, fn))
    print('wil6210/wil6436 files: %d' % len(fw))
    if args.list:
        for p in sorted(fw):
            print('  %8d  %s' % (os.path.getsize(p), os.path.relpath(p, out)))
    wl = os.path.join(out, 'nova/bin/wireless')
    if os.path.exists(wl):
        print('decryptor binary: %s (%d B) -- AES/crypto in libcrypto'
              % (os.path.relpath(wl, out), os.path.getsize(wl)))

if __name__ == '__main__':
    main()
