#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decrypt MikroTik-encrypted wil6210 firmware / board files.

Reversed scheme (nova/bin/wireless, FUN_000a540c): a fixed high-entropy keystream
is XORed over the file. The keystream is CONSTANT within a "crypto epoch" (shared
by fw + all boards) and MikroTik rotated it only a few times across releases; some
epochs ship fw and/or boards as plaintext (no encryption). key derivation in-binary
is key32 = Hash^1024(seed) expanded to the keystream, but empirically only a handful
of distinct keystreams exist, so we carry them as a library and auto-detect.

Recovered keystreams (keystreams/ next to this script, or $WIL_KEYSTREAMS):
  ks_58cfa159  dominant: RouterOS 6.2.x(BETA), 6.45, 6.46, 6.47 (boards)
  ks_f0e9cbc5  6.43.13, 6.44.5
  ks_967e9839  6.43.12
  ks_6953384a  6.48.6, 6.49beta54 (boards)
Plaintext epochs (no key needed): 6.41, 6.42 (fw+boards); 6.46+ fw.

Plaintext markers: fw/board container = `06 00 00 00 34 .. 30 31 32 36` ("0126");
older board wrapper = nv::message `02 00 00 00 <len> 00 78 91 00 f0 bd f0 bd`.

Usage:
  npk_decrypt.py --auto FILE...              # try every known keystream, pick valid
  npk_decrypt.py --keystream KS FILE -o OUT  # decrypt with a specific keystream
  npk_decrypt.py --recover CIPHER PLAIN -o KS # recover keystream from a known pair
"""
import argparse, os, sys, glob

KSDIR = os.environ.get('WIL_KEYSTREAMS', os.path.join(os.path.dirname(__file__), 'keystreams'))

def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def is_plain(d):
    return d[:4] in (b'\x06\x00\x00\x00', b'\x02\x00\x00\x00')  # 0126 container / nv::message
def load_lib():
    return {os.path.basename(p): open(p, 'rb').read()
            for p in sorted(glob.glob(os.path.join(KSDIR, 'ks_*.bin')))}

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*')
    ap.add_argument('--auto', action='store_true', help='auto-detect keystream from library')
    ap.add_argument('--keystream')
    ap.add_argument('--recover', nargs=2, metavar=('CIPHER', 'PLAIN'))
    ap.add_argument('-o', '--output')
    a = ap.parse_args()

    if a.recover:
        ks = xor(open(a.recover[0], 'rb').read(), open(a.recover[1], 'rb').read())
        open(a.output, 'wb').write(ks)
        print('recovered keystream %d bytes -> %s (prefix %s)' % (len(ks), a.output, ks[:4].hex()))
        return

    if a.auto:
        lib = load_lib()
        for fn in a.files:
            c = open(fn, 'rb').read()
            if is_plain(c):
                print('%-46s ALREADY PLAINTEXT (%s)' % (os.path.basename(fn), c[:4].hex())); continue
            done = False
            for name, ks in lib.items():
                if len(ks) >= len(c):
                    d = xor(c, ks[:len(c)])
                    if is_plain(d):
                        out = fn + '.dec'; open(out, 'wb').write(d)
                        print('%-46s %-16s -> %s  [%s]' % (os.path.basename(fn), name, out, d[:4].hex()))
                        done = True; break
            if not done:
                print('%-46s NO KNOWN KEYSTREAM (bootstrap via --recover from a known board pair)' % os.path.basename(fn))
        return

    if a.keystream and a.files:
        ks = open(a.keystream, 'rb').read()
        for fn in a.files:
            c = open(fn, 'rb').read()
            if len(c) > len(ks): sys.exit('keystream too short for %s' % fn)
            d = xor(c, ks[:len(c)])
            out = a.output if (a.output and len(a.files) == 1) else fn + '.dec'
            open(out, 'wb').write(d)
            print('%-46s -> %s  [%s]' % (os.path.basename(fn), out, 'OK' if is_plain(d) else 'WARN wrong ks'))
        return
    ap.error('need --auto, --keystream, or --recover')

if __name__ == '__main__':
    main()
