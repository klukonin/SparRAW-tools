# MikroTik wil6210 keystream library

XOR keystreams recovered from the RouterOS `wireless` packages. The encryption is a
**fixed high-entropy keystream XORed over the file**; the same stream covers a version's
firmware AND its board files. MikroTik rotated the keystream only a few times ("crypto
epochs") and ships some files as plaintext. Load with `npk_decrypt.py --auto`.

| keystream       | len   | used by (board decrypt)                          |
|-----------------|-------|--------------------------------------------------|
| ks_58cfa159.bin | 561252| 6.2.x(BETA), 6.45.3, 6.46.x, 6.47beta19          |
| ks_f0e9cbc5.bin | 561252| 6.43.13, 6.44.5                                  |
| ks_967e9839.bin | 561160| 6.43.12                                          |
| ks_6953384a.bin | 6668  | 6.48.6, 6.49beta54                               |

Plaintext epochs (no key): 6.41.x, 6.42.1 (fw+boards); 6.46+ (fw only, boards still ENC).

Recovering a new epoch's keystream: decrypt any board of a known epoch to get its
plaintext, then `npk_decrypt.py --recover new_epoch_board.brd known_plaintext.bin -o ks_new.bin`
(board plaintext is shared across epochs for the same board model — verified consistent).
