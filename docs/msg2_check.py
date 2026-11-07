#!/usr/bin/env python3
"""
Offline verification of the Kotlin HKDF2 used in NoiseState.mixKey().

Given ck_before, ikm (the input to MixKey; for the ee step this is the
ECDH shared secret 'ee'), the function prints HKDF2(ck_before, ikm) =
(ck_after, k_after), split from HKDF-SHA256(ikm, salt=ck_before, info=empty, 64).

Usage:
  python3 msg2_check.py <ck_before_hex> <ikm_hex>

The values come from the logcat lines:
  msg2-check ck_before_ee = ...
  msg2-check ee           = ...
and should match:
  after MixKey(ee) ck = ...
  after MixKey(ee) k  = ...
"""

import hashlib, hmac, sys

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]

def hkdf2(ck_before: bytes, ikm: bytes):
    out = hkdf(ikm, ck_before, b"", 64)
    return out[:32], out[32:64]

def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    ck_before = bytes.fromhex(sys.argv[1])
    ikm = bytes.fromhex(sys.argv[2])
    ck_after, k_after = hkdf2(ck_before, ikm)
    print(f"ck_before = {ck_before.hex()}")
    print(f"ikm       = {ikm.hex()}")
    print(f"ck_after  = {ck_after.hex()}")
    print(f"k_after   = {k_after.hex()}")
    print()
    print("Compare with the logcat lines:")
    print('  after MixKey(ee) ck = ...')
    print('  after MixKey(ee) k  = ...')

if __name__ == "__main__":
    main()
