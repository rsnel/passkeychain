#!/usr/bin/env python3
"""Test vectors for docs/PROTOCOL.md section 18, computed independently of the
app (Python + the 'cryptography' package). Prints the section as Markdown.

    python3 docs/protocol-vectors.py > /tmp/vectors.md

The app's unit tests check the same values (NoiseHandshakeTest,
ProtocolVectorsTest), so the document, this script and the code agree.
"""
import hashlib, hmac, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

hx = lambda b: b.hex()


# ---- small helpers -----------------------------------------------------------------------

def hkdf(ikm, salt, info, n):
    prk = hmac.new(salt if salt else b"\0"*32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]

def key(scalar_byte):
    return ec.derive_private_key(int.from_bytes(bytes([scalar_byte])*32, "big"), ec.SECP256R1())

def pub(k, compressed=False):
    return k.public_key().public_bytes(serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint if compressed else serialization.PublicFormat.UncompressedPoint)

def dh(priv, pub65):
    return priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub65))

def cbor(v):
    """Canonical CBOR for the few types used here."""
    def head(major, n):
        if n < 24: return bytes([major << 5 | n])
        if n < 256: return bytes([major << 5 | 24, n])
        if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
        if n < 2**32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
        return bytes([major << 5 | 27]) + struct.pack(">Q", n)
    if v is True: return b"\xf5"
    if v is False: return b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())
        items.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def qr_digits(data):
    """7-byte chunks, little-endian, 17 digits each; a final chunk of 1-6 bytes as 3,5,8,10,13,15 digits."""
    widths = {1: 3, 2: 5, 3: 8, 4: 10, 5: 13, 6: 15, 7: 17}
    out = ""
    for i in range(0, len(data), 7):
        chunk = data[i:i+7]
        out += str(int.from_bytes(chunk, "little")).zfill(widths[len(chunk)])
    return out


# ---- 1. QR code --------------------------------------------------------------------------

s_i = key(0x11)                                   # the browser's QR key pair
qr_secret = bytes(range(16))                      # 00 01 .. 0f
qr_map = {0: pub(s_i, compressed=True), 1: qr_secret, 2: 2, 3: 1794135600, 4: False, 5: "ga"}
qr_cbor = cbor(qr_map)
qr_text = "FIDO:/" + qr_digits(qr_cbor)

# ---- 2. keys from the QR secret ------------------------------------------------------------

label = lambda n: struct.pack("<I", n)
eid_key = hkdf(qr_secret, b"", label(1), 64)
aes_key, hmac_key = eid_key[:32], eid_key[32:]
tunnel_id = hkdf(qr_secret, b"", label(2), 16)

# ---- 3. the advert ---------------------------------------------------------------------------

nonce10 = bytes(range(0xa0, 0xaa))                # a0 .. a9
routing_id = bytes.fromhex("c0ffee")
def eid_plain(domain):
    return b"\x00" + nonce10 + routing_id + struct.pack("<H", domain)
def advert(plain):
    enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    ct = enc.update(plain) + enc.finalize()
    return ct + hmac.new(hmac_key, ct, hashlib.sha256).digest()[:4]
plain0, plain266 = eid_plain(0), eid_plain(266)
adv0, adv266 = advert(plain0), advert(plain266)
psk_derived = hkdf(qr_secret, plain0, label(3), 32)

# ---- 4. Noise KNpsk0 (fixed keys, fixed psk: the vector of NoiseHandshakeTest) ---------------

class SymmetricState:
    def __init__(self, name):
        self.h = name.ljust(32, b"\0") if len(name) <= 32 else hashlib.sha256(name).digest()
        self.ck = self.h; self.k = None
    def mix_hash(self, d): self.h = hashlib.sha256(self.h + d).digest()
    def mix_key(self, ikm):
        o = hkdf(ikm, self.ck, b"", 64); self.ck, self.k = o[:32], o[32:]
    def mix_key_and_hash(self, ikm):
        o = hkdf(ikm, self.ck, b"", 96); self.ck = o[:32]; self.mix_hash(o[32:64]); self.k = o[64:]
    def encrypt_and_hash(self, p):
        c = AESGCM(self.k).encrypt(b"\0"*12, p, self.h); self.mix_hash(c); return c
    def decrypt_and_hash(self, c):
        p = AESGCM(self.k).decrypt(b"\0"*12, c, self.h); self.mix_hash(c); return p
    def split(self):
        o = hkdf(b"", self.ck, b"", 64); return o[:32], o[32:]

e_i, e_r = key(0x22), key(0x33)
psk = bytes(range(32))
s_i_pub = pub(s_i)

def init():
    st = SymmetricState(b"Noise_KNpsk0_P256_AESGCM_SHA256")
    steps = [("h = ck after init (name padded to 32 bytes)", st.h)]
    st.mix_hash(b"\x01"); steps.append(("h after MixHash(prologue 0x01)", st.h))
    st.mix_hash(s_i_pub); steps.append(("h after MixHash(s_i, uncompressed)", st.h))
    st.mix_key_and_hash(psk); steps.append(("ck after MixKeyAndHash(psk)", st.ck)); steps.append(("h after MixKeyAndHash(psk)", st.h))
    return st, steps

# initiator (the browser) writes msg1
ini, steps = init()
ini.mix_hash(pub(e_i)); ini.mix_key(pub(e_i))
msg1 = pub(e_i) + ini.encrypt_and_hash(b"")
# responder (the phone) reads msg1, writes msg2
res, _ = init()
res.mix_hash(msg1[:65]); res.mix_key(msg1[:65]); res.decrypt_and_hash(msg1[65:])
steps.append(("h after msg1", res.h))
res.mix_hash(pub(e_r)); res.mix_key(pub(e_r))
res.mix_key(dh(e_r, msg1[:65]))                   # ee
res.mix_key(dh(e_r, s_i_pub))                     # se
msg2 = pub(e_r) + res.encrypt_and_hash(b"")
k1, k2 = res.split()
# the initiator accepts msg2 and agrees
ini.mix_hash(msg2[:65]); ini.mix_key(msg2[:65])
ini.mix_key(dh(e_i, msg2[:65])); ini.mix_key(dh(s_i, msg2[:65])); ini.decrypt_and_hash(msg2[65:])
assert ini.h == res.h and ini.split() == (k1, k2)

# ---- 5. transport ------------------------------------------------------------------------------

def crypter_pad(p):
    size = (len(p) + 1 + 31) // 32 * 32
    zeros = size - len(p) - 1
    return p + b"\0"*zeros + bytes([zeros])
def nonce(n): return b"\0"*8 + struct.pack(">I", n)
def seal(k, n, p): return AESGCM(k).encrypt(nonce(n), crypter_pad(p), None)
tx0 = seal(k2, 0, bytes.fromhex("00a0"))
tx1 = seal(k2, 1, b"x"*40)
rx0_plain = bytes.fromhex("02a1016161")
rx0 = seal(k1, 0, rx0_plain)

def post_pad(cbor_bytes):
    size = (len(cbor_bytes) + 2 + 511) // 512 * 512
    n = size - len(cbor_bytes) - 2
    return cbor_bytes + b"\0"*n + struct.pack("<H", n)
pp = post_pad(b"\x07"*100)

# ---- 6. tunnel server names ----------------------------------------------------------------------

def hostname(n):
    v = struct.unpack("<Q", hashlib.sha256(b"caBLEv2 tunnel server domain" + struct.pack("<H", n) + b"\0").digest()[:8])[0]
    tld = ["com", "org", "net", "info"][v & 3]; v >>= 2; label = ""
    while v: label += "abcdefghijklmnopqrstuvwxyz234567"[v & 31]; v >>= 5
    return f"cable.{label}.{tld}"
assert hostname(266) == "cable.wufkweyy3uaxb.com"   # Chromium's own test value


# ---- print ----------------------------------------------------------------------------------------

def block(lines):
    w = max(len(k) for k, _ in lines)
    return "```text\n" + "\n".join(f"{k.ljust(w)}  {v}" for k, v in lines) + "\n```\n"

print(f"""## 18. Test vectors

Computed by [`docs/protocol-vectors.py`](protocol-vectors.py), an independent
implementation in Python, which prints this section. PassKeyChain's unit tests
check the same values (`ProtocolVectorsTest`, `NoiseHandshakeTest`). All
values are hex unless noted. Private keys are fixed for reproducibility:
P-256 scalars of 32 equal bytes, `0x11..11` for the browser's QR key `s_i`,
`0x22..22` for its ephemeral `e_i`, `0x33..33` for the phone's ephemeral `e_r`.

### 18.1 QR code

The QR map ([section 2](#2-qr-code-contents)) with the browser's public key, the
QR secret `00 01 .. 0f`, 2 known tunnel server domains, time 1794135600, no
linking, hint `"ga"`:

{block([("CBOR", hx(qr_cbor)), ("QR text", qr_text)])}
### 18.2 Keys from the QR secret

[Section 3](#3-key-derivation-from-the-qr-secret):

{block([("EID AES key", hx(aes_key)), ("EID HMAC key", hx(hmac_key)), ("tunnel id", hx(tunnel_id))])}
The phone connects to `wss://cable.ua5v.com/cable/new/{hx(tunnel_id)}`.

### 18.3 Advert and PSK

[Section 5](#5-ble-advertisement-eid), with nonce `a0 a1 .. a9`, routing id `c0ffee`:

{block([("EID plaintext (domain 0)", hx(plain0)), ("advert (domain 0)", hx(adv0)),
        ("EID plaintext (domain 266)", hx(plain266)), ("advert (domain 266)", hx(adv266)),
        ("psk (domain 0 plaintext)", hx(psk_derived))])}
Domain 266 is the computed server `{hostname(266)}` ([section 4](#4-tunnel-server-websocket-setup)); its
number appears little-endian in bytes 14–15 (`0a01`), and it changes the
advert and the psk.

### 18.4 Noise handshake

[Section 6](#6-noise-handshake), with the fixed keys above and, so that this
vector stands on its own, the psk `00 01 .. 1f` rather than the one from 18.3:

{block([("s_i (uncompressed)", hx(s_i_pub)), ("e_i", hx(pub(e_i))), ("e_r", hx(pub(e_r))), ("psk", hx(psk))] + [(k, hx(v)) for k, v in steps])}
{block([("msg1 (browser)", hx(msg1)), ("msg2 (phone)", hx(msg2)), ("handshake hash", hx(res.h))])}
### 18.5 Transport

[Sections 7, 10 and 11](#7-transport-keys): `k1` the phone receives with, `k2`
it sends with; every record is Crypter-padded to 32 bytes and sealed with
AES-256-GCM, no additional data, nonce `00`×8 ‖ counter (big-endian).

{block([("k1 (browser -> phone)", hx(k1)), ("k2 (phone -> browser)", hx(k2)),
        ("nonce, counter 1", hx(nonce(1))),
        ("phone sends 00a0, counter 0", hx(tx0)),
        ("phone sends 'x'*40, counter 1", hx(tx1)),
        ("phone receives, counter 0", hx(rx0)),
        ("... which opens to", hx(rx0_plain))])}
Post-handshake padding: a 100-byte CBOR map is padded to 512 bytes, ending in
`{hx(pp[-2:])}` (410 padding bytes, little-endian); a 511-byte map to 1024.

### 18.6 Tunnel server names

[Section 4](#4-tunnel-server-websocket-setup):

{block([("256", hostname(256)), ("266", hostname(266) + "   (Chromium's test value)"), ("65535", hostname(65535))])}""")

# the Kotlin test constants, for checking by hand
import sys
print(f"// QR_TEXT={qr_text}\n// AES={hx(aes_key)} HMAC={hx(hmac_key)} TUNNEL={hx(tunnel_id)}\n// ADV0={hx(adv0)} ADV266={hx(adv266)} PSK={hx(psk_derived)}\n// MSG1={hx(msg1)}\n// MSG2={hx(msg2)}\n// K1={hx(k1)} K2={hx(k2)} H={hx(res.h)}\n// TX0={hx(tx0)}\n// TX1={hx(tx1)}\n// RX0={hx(rx0)}", file=sys.stderr)
