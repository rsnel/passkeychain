# caBLE v2 (hybrid transport): complete protocol notes

This document records everything needed to implement a working caBLE v2
authenticator (phone side, responder) that interoperates with Chrome on the
desktop as the initiator. It was derived from:

- Chromium source (`device/fido/cable/*`, especially `v2_handshake.cc`,
  `noise.cc`, `v2_authenticator.cc` and `fido_tunnel_device.cc`);
- the published specifications listed below;
- live logs of a working implementation (PassKeyChain, `hybrid/*.kt`);
- offline verification of the cryptographic steps.

Published specifications the protocol builds on:

| Specification | Used for |
|---|---|
| [FIDO CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html) | The hybrid transport itself (QR code, BLE advert, tunnel, handshake). This document was written from Chromium and live runs, not checked clause by clause against it. |
| [FIDO CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) | The CTAP2 commands, status codes, getInfo, and canonical CBOR ([sections 8, 9, 13](#9-ctap2-exchange-over-the-tunnel)) |
| [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | authenticatorData, flags (UP, UV, BE, BS, AT), signatures, attestation "none" |
| [The Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34) | The handshake ([section 6](#6-noise-handshake)): pattern notation, MixHash, MixKey, the psk rules, Split |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) HKDF, [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) HMAC | All key derivation ([section 3](#3-key-derivation-from-the-qr-secret)) and the advert tag |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) AES-GCM, [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) AES | Noise and transport encryption; the advert (AES-256, one ECB block) |
| [SEC 1 v2](https://www.secg.org/sec1-v2.pdf), [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) | P-256 points (compressed 33 / uncompressed 65 bytes), ECDH, ECDSA |
| [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) CBOR, [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) COSE algorithms | QR payload, CTAP2 messages, the COSE_Key in a new credential |
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) WebSocket | The connections to the tunnel server ([section 4](#4-tunnel-server-websocket-setup)) |
| [Bluetooth Core Specification](https://www.bluetooth.com/specifications/specs/core-specification/) | The BLE advertisement (service data, advertising channels) |

How sure each statement is, is marked where it matters:

| Marker | Meaning |
|---|---|
| **[verified]** | Observed to work against Chrome with a real sign-in, or cross-checked offline against values Chrome produced |
| **[spec]** | From the Noise, CTAP 2.1 or WebAuthn specification |
| **[chromium]** | Read from Chromium source, not separately observed |
| **[unverified]** | Plausible, but the runs so far cannot tell (for example because the value involved was always 0) |

## Contents

1. [Roles and overall flow](#1-roles-and-overall-flow)
2. [QR code contents](#2-qr-code-contents)
3. [Key derivation from the QR secret](#3-key-derivation-from-the-qr-secret)
4. [Tunnel server WebSocket setup](#4-tunnel-server-websocket-setup)
5. [BLE advertisement (EID)](#5-ble-advertisement-eid)
6. [Noise handshake](#6-noise-handshake)
7. [Transport keys](#7-transport-keys)
8. [Post-handshake message](#8-post-handshake-message)
9. [CTAP2 exchange over the tunnel](#9-ctap2-exchange-over-the-tunnel)
10. [Padding and framing summary](#10-padding-and-framing-summary)
11. [Nonce construction](#11-nonce-construction)
12. [MessageType byte](#12-messagetype-byte)
13. [Canonical CBOR ordering](#13-canonical-cbor-ordering)
14. [Quirks and gotchas](#14-quirks-and-gotchas)
15. [Security requirements](#15-security-requirements)
16. [Debugging checklist](#16-debugging-checklist)
17. [Reference: constants](#17-reference-constants)
18. [Test vectors](#18-test-vectors)

## 1. Roles and overall flow

Desktop (Chrome) is the **initiator**. Phone (authenticator) is the **responder**.

1. Chrome shows a QR code.
2. The phone scans the QR, parses the CBOR payload, and derives keys.
3. The phone connects to the tunnel server at `/cable/new/<tunnelId>`.
4. The tunnel server returns a 3-byte routing ID in the response header
   `X-Cable-Routing-Id`.
5. The phone builds an EID (encrypted BLE advertisement) with that routing ID,
   encrypts it, and advertises it over BLE on service UUID `0xFFF9`.
6. Chrome scans BLE and finds an advert that decrypts and authenticates under
   the EID key from its own QR secret. That proves a phone holding the QR
   secret is physically nearby, and gives Chrome the routing ID. (Chrome
   already knows the tunnelId: it derives it from the QR secret just like the
   phone.) Chrome connects to `/cable/connect/<routingId>/<tunnelId>`.
7. The tunnel server pairs the two WebSocket connections.
8. Chrome sends Noise handshake message 1 (msg1).
9. The phone decrypts msg1, builds msg2 and sends it. The phone can stop
   advertising now.
10. Chrome accepts msg2 and derives the transport keys.
11. The phone sends the post-handshake message (features + getInfo).
12. Chrome accepts the post-handshake message.
13. Chrome sends a CTAP2 getAssertion (or makeCredential).
14. The phone asks the user, signs, and returns the CTAP2 response.
15. The tunnel is closed; the RP verifies the assertion.

The phone must connect to `/cable/new/` **before** advertising BLE, because
the routing ID in the EID comes from the tunnel server's response headers,
and Chrome will not connect to `/cable/connect/` until it sees the EID.
**[verified]**

## 2. QR code contents

The QR is a `FIDO:/` string followed by decimal digits. The digits decode to a
CBOR map with these keys **[verified for 0–5]**:

| Key | Contents |
|---|---|
| 0 | Compressed P-256 public key (33 bytes, prefix `0x02` or `0x03`) |
| 1 | QR secret (16 bytes) |
| 2 | Number of known tunnel server domains (integer) |
| 3 | Current unix time (integer, seconds) |
| 4 | Whether the desktop supports state-assisted transactions (linking), boolean. A CBOR boolean is major type 7: a decoder without major type 7 fails here. |
| 5 | Request hint: `"ga"` (getAssertion) or `"mc"` (makeCredential) |

The public key in field 0 is the **desktop's** static public key, not the
phone's. The QR secret in field 1 is the input to all key derivation.

**Digit encoding:** the byte string is cut into chunks of 7 bytes; each chunk
is read as a little-endian integer and written as exactly 17 decimal digits.
A final partial chunk of 1, 2, 3, 4, 5 or 6 bytes is written as 3, 5, 8, 10,
13 or 15 digits. **[verified]**

An `"mc"` hint means the site wants to **create** a passkey; see
makeCredential in [section 9](#9-ctap2-exchange-over-the-tunnel). An
authenticator that cannot create passkeys should say so right after the scan,
instead of after the whole exchange.

## 3. Key derivation from the QR secret

All derivations use HKDF-SHA256 with an **empty** salt unless noted (HKDF
treats an empty salt as 32 zero bytes). `info` is a 4-byte **little-endian**
integer label, Chromium's `DerivedValueType` **[chromium]**:

| Label | Value | Used |
|---|---|---|
| 1 | EID key | here |
| 2 | Tunnel ID | here |
| 3 | PSK | here |
| 4 | Paired secret | state-assisted (linked) flow only |
| 5 | Identity-key seed | state-assisted flow only |
| 6 | Per-contact-ID secret | state-assisted flow only |

Only 1, 2 and 3 are needed for the QR flow. In particular the phone has
**no** static key of its own in this flow; do not derive one.

```text
QR secret = the 16 bytes from QR field 1

EID AES key and EID HMAC key:
  material = HKDF(ikm=QRsecret, salt=empty, info=[1,0,0,0], len=64)
  aesKey   = material[0..32]          (32 bytes: AES-256)
  hmacKey  = material[32..64]

tunnelId (used in the tunnel server URL):
  tunnelId = HKDF(ikm=QRsecret, salt=empty, info=[2,0,0,0], len=16)

Noise PSK:
  psk = HKDF(ikm=QRsecret, salt=eidPlaintext, info=[3,0,0,0], len=32)
```

`eidPlaintext` is the full 16-byte EID plaintext (see
[section 5](#5-ble-advertisement-eid)). Note the salt: the 16-byte EID
plaintext, not empty.

The tunnelId derivation is confirmed: it matches the tunnelId Chrome prints in
its own `/cable/connect/<routing>/<tunnelId>` URL, character for character,
for the same QR. **[verified]**

The psk derivation is confirmed: msg1 from Chrome decrypts with it, and an
offline HKDF computation gives the same value. **[verified]**

## 4. Tunnel server WebSocket setup

```text
Phone:   wss://cable.ua5v.com/cable/new/<hex(tunnelId)>
Chrome:  wss://cable.ua5v.com/cable/connect/<hex(routingId)>/<hex(tunnelId)>
```

The tunnelId is lowercase hex, no dashes. The routingId is the 3-byte value
the server assigns (also lowercase hex, 6 characters).

Other tunnel servers **[chromium]**: the browser connects to the server
whose number the phone put in EID bytes 14–15. Numbers 0–255 are a list built
into the browser (QR field 2 says how long the browser's list is). For
256–65535 the browser computes the hostname (`tunnelserver::DecodeDomain`):

```text
digest = SHA-256("caBLEv2 tunnel server domain" || number (2 bytes, LE) || 0x00)
v      = digest[0..8] as a little-endian 64-bit integer
tld    = ["com", "org", "net", "info"][v & 3]
label  = base32 ("a"-"z", "2"-"7") of v >> 2, least significant 5 bits first
host   = "cable." + label + "." + tld        (266 -> cable.wufkweyy3uaxb.com)
```

PassKeyChain can use such a server (Tunnel server setting; `server/` has a
server and a script that lists the names). **[unverified]** against Chrome so far.

WebSocket upgrade **[verified]**:

- Send the header `Sec-WebSocket-Protocol: fido.cable`. **Without it the
  server returns `400 Bad Request`.**
- The successful response contains a header `X-Cable-Routing-Id` with the
  3-byte routing ID in hex. HTTP header names are case-insensitive;
  PassKeyChain also accepts the older name `X-caBLE-Shard`.

**Important:** the phone and Chrome connect to **different** paths. The phone
uses `/cable/new/`, Chrome uses `/cable/connect/`. Using `/cable/connect/`
from the phone returns a WebSocket that never gets paired. **[verified]**

The routing ID is **not** used in the phone's own `/cable/new/` URL. It is
only used (a) in the EID plaintext, and (b) by Chrome in its
`/cable/connect/` URL.

## 5. BLE advertisement (EID)

Service UUID: `0000FFF9-0000-1000-8000-00805F9B34FB`

The EID plaintext is 16 bytes:

| Bytes | Contents |
|---|---|
| 0 | `0x00` |
| 1–10 | 10 fresh random bytes (`kNonceSize` = 10), new for every sign-in |
| 11–13 | The 3-byte routing ID from `X-Cable-Routing-Id` |
| 14–15 | The 2-byte tunnel server domain, little-endian: 0 for `cable.ua5v.com`. Chromium copies its `uint16_t` with `memcpy` (`eid::FromComponents`), so native byte order, which is little-endian on phones and PCs. **[chromium]** Numbers 256–65535 are computed hostnames; see [section 4](#4-tunnel-server-websocket-setup). |

The 20-byte BLE payload **[verified]**:

```text
ciphertext = AES-256-ECB(key = aesKey (all 32 bytes), plaintext = eidPlaintext)
             one 16-byte block, no padding
tag        = HMAC-SHA256(key = hmacKey, message = ciphertext)[0..4]
payload    = ciphertext || tag                               (20 bytes)
```

(An earlier version of these notes said AES-128 with the first 16 bytes of
aesKey. That was wrong: the working implementation passes all 32 bytes to
AES, which makes it AES-256, and Chrome accepts the advert.)

Chrome decrypts this, validates the HMAC, and extracts the routing ID from the
plaintext.

The random bytes 1–10 do not appear anywhere else in the protocol, but they
are part of the PSK salt ([section 3](#3-key-derivation-from-the-qr-secret)):
the PSK is derived from the **whole** plaintext. So the plaintext you use for
the psk derivation must be exactly the bytes you encrypt into the
advertisement. If you build one and encrypt another, the psk will not match
and msg1 will fail to decrypt. **[verified]**

## 6. Noise handshake

Protocol name: `Noise_KNpsk0_P256_AESGCM_SHA256`

For QR-initiated sign-ins Chrome uses the **KNpsk0** pattern with prologue
`0x01`. **[verified]** Chromium also has NKpsk0 with prologue `0x00`, for
state-assisted (linked) transactions; it does not work for the QR flow.
**[chromium]**

Chromium's initiator (`HandshakeInitiator`) selects the pattern from what it
holds:

- a peer identity (a linked phone), no local identity: NKpsk0, prologue `0x00`;
- a local identity (its QR key pair), no peer identity: KNpsk0, prologue `0x01`.

In the QR flow the desktop has a local identity (the key pair whose public half
is in the QR) and knows no phone key, so it uses KNpsk0.

**Noise notation**, as the Noise specification writes handshake patterns
(its section 7): each line is one message, `->` from the initiator (Chrome)
and `<-` from the responder (the phone). The tokens say what that message
does, in order:

- `e`: the sender makes an ephemeral key pair and sends its public key;
- `s`: the sender's long-term (static) public key;
- `ee`, `se`, `es`, `ss`: a Diffie-Hellman between the two parties' keys,
  first letter the initiator's key, second the responder's (`se` = initiator
  static with responder ephemeral), mixed into the keys;
- `psk`: the pre-shared key is mixed in.

Lines above `...` are pre-messages: keys both sides know before the
handshake starts (here from the QR code). The pattern's name says the same
in short: **K** = the initiator's static key is **K**nown to the responder in
advance, **N** = the responder has **N**o static key, **psk0** = the psk is
mixed in at the start of the first message.

KNpsk0, with `s` the desktop's static key, known to both sides in advance:

```text
-> s                 (pre-message: the QR key, mixed in at init)
...
-> psk, e            msg1, from Chrome
<- e, ee, se         msg2, from the phone
```

Two rules from the Noise specification explain steps that look odd **[spec]**:

- In any handshake with a PSK, every `e` token is processed as
  `MixHash(e.public)` followed by `MixKey(e.public)` (Noise spec, section 9,
  "Pre-shared symmetric keys"). This is standard Noise, not a Chromium quirk.
- `se` in a responder's message means DH(initiator's static key, responder's
  ephemeral key).

### Initialisation (responder)

```text
h  = protocolName padded with zero bytes to 32 bytes
     (the name is 31 bytes, so one zero byte)
ck = h

MixHash([0x01])                 // prologue, single byte 0x01
MixHash(peerIdentity65)         // the QR's public key, uncompressed (pre-message s)
MixKeyAndHash(psk)              // 32-byte psk
```

`peerIdentity65` is the decompression of the 33-byte QR public key to 65-byte
uncompressed P-256 (`0x04 || X || Y`). If the QR key starts with `0x02` choose
the even Y, if `0x03` the odd Y.

`MixKeyAndHash(ikm)`: `(ck, temp_h, temp_k) = HKDF(ikm, salt=ck, info=empty,
len=96)` split in thirds; `MixHash(temp_h)`; `k = temp_k`; `nonce = 0`.

### msg1 (from Chrome: 81 bytes = e_pub 65 + tag 16)

```text
check that e_pub_i is a valid point on P-256; abort if not
MixHash(e_pub_i)                    // 65 bytes, uncompressed P-256
MixKey(e_pub_i)                     // psk rule: e is also mixed into the key
plaintext = DecryptAndHash(tag1)    // must be empty
```

If `DecryptAndHash` throws, the psk or the initial h/ck chain is wrong. If it
succeeds and the plaintext is empty, msg1 is correctly processed.

### msg2 (from the phone: 81 bytes = e_pub 65 + tag 16)

Generate a fresh P-256 ephemeral key pair `ephR`.

```text
MixHash(e_pub_r)                        // 65 bytes, uncompressed P-256
MixKey(e_pub_r)                         // psk rule
ee = ECDH(ephR_priv, e_pub_i)
MixKey(ee)
se = ECDH(ephR_priv, peerIdentity65)    // initiator static x responder ephemeral
MixKey(se)
tag2 = EncryptAndHash(empty)            // 16-byte AEAD tag
msg2 = e_pub_r || tag2
```

Chromium's `RespondToHandshake` does, in order **[chromium, verified]**:

```text
MixHash(peer_point_bytes)
MixKey(peer_point_bytes)
MixKey(shared_key_ee)
if (peer_identity) MixKey(shared_key_se)
EncryptAndHash({})
```

Missing `se` makes msg2 fail with "Invalid caBLE handshake message" (the AEAD
tag verifies against a different k than Chrome's). **[verified]**

### No further handshake messages

After msg2 the handshake is complete. The transport keys are derived
([section 7](#7-transport-keys)) and the post-handshake message is sent
([section 8](#8-post-handshake-message)).

## 7. Transport keys

After msg2, the standard Noise `Split()` **[spec, verified]**:

```text
(k1, k2) = HKDF(ikm=empty, salt=ck, info=empty, len=64), split in halves

k1 encrypts initiator -> responder: the phone RECEIVES with k1
k2 encrypts responder -> initiator: the phone SENDS with k2
```

Chromium's `Crypter` calls them `read_key` and `write_key` from the phone's
point of view, which is the same assignment.

Getting this backwards produces "decryption failed for caBLE post-handshake
message" even though the handshake and msg2 were accepted. **[verified]**

## 8. Post-handshake message

After msg2 the phone sends a CBOR map with its features and a getInfo
response. Chrome will not send the CTAP2 request until it receives this.
**[verified]**

CBOR map (top level):

| Key | Contents |
|---|---|
| 1 | getInfo response, as a CBOR byte string |
| 2 | Linking information (optional; only for state-assisted flows, which this document does not cover) **[chromium]** |
| 3 | Features array, e.g. `["ctap"]` |

getInfo response (nested CBOR map), as PassKeyChain sends it:

| Key | Contents |
|---|---|
| 1 | versions: `["FIDO_2_0", "FIDO_2_1"]` |
| 3 | aaguid: 16 bytes (zeros are acceptable) |
| 4 | options: `{"rk": true, "uv": true}`. `"uv": true` promises built-in user verification: only claim it if the phone really unlocks before signing. |
| 9 | transports: `["cable", "hybrid", "internal"]` (`"cable"` is not a WebAuthn transport name; Chrome ignores it) |
| 10 | algorithms: `[{"alg": -7, "type": "public-key"}]` |

Key 2 (extensions) is omitted: advertise only extensions you implement.
(Earlier versions sent `["prf"]` without implementing PRF.)

Map keys must be in canonical order ([section 13](#13-canonical-cbor-ordering)):
`"rk"` before `"uv"`.

Two padding layers are applied before encryption **[verified]**:

```text
Layer A, EncodePaddedCBORMap (application layer):
  encode the CBOR map to bytes: L bytes
  padded_size = round_up(L + 2, 512)
  num_padding = padded_size - L - 2
  padded      = CBOR || num_padding zero bytes || uint16_le(num_padding)

Layer B, Crypter::Encrypt padding (transport layer):
  padded_size = round_up(len + 1, 32)
  num_zeros   = padded_size - len - 1
  padded      = bytes || num_zeros zero bytes || uint8(num_zeros)
```

The two layers are separate. Applying only layer A produces "Invalid padding
in caBLE handshake message". Applying neither produces "decryption failed for
caBLE post-handshake message".

After layer B the plaintext is encrypted with the send key (k2) and the
current send nonce, and sent as a raw WebSocket payload (no length prefix).

## 9. CTAP2 exchange over the tunnel

Chrome sends the CTAP2 request as a raw WebSocket payload, encrypted with k1
and the current receive nonce.

The decrypted plaintext begins with the CTAP2 command byte, followed by the
CBOR parameters, if any **[spec]**:

| Byte | Command |
|---|---|
| `0x01` | authenticatorMakeCredential |
| `0x02` | authenticatorGetAssertion |
| `0x04` | authenticatorGetInfo (no parameters: the message is one byte) |
| `0x0B` | authenticatorSelection (not seen in the hybrid flow) |

There is **no** MessageType prefix on CTAP2 requests in the observed flow; see
[section 12](#12-messagetype-byte) for the exceptions seen.

### getAssertion request

The CBOR map contains **[spec]**:

| Key | Contents |
|---|---|
| 1 | rpId (string) |
| 2 | clientDataHash (32 bytes) |
| 3 | allowList: array of `{"id": bytes, "type": "public-key"}`, optional |
| 4 | extensions, optional |
| 5 | options, optional, e.g. `{"up": true, "uv": true}` |
| 6, 7 | pinUvAuthParam / pinUvAuthProtocol (not used in hybrid) |

Choosing the credential:

- Only passkeys whose stored rpId equals the request's rpId qualify.
- Non-empty allowList: only passkeys whose credential id is in it.
- Empty allowList: any passkey for the rpId (a "discoverable" sign-in without
  username); if several qualify, let the user pick.
- None qualify: answer `0x2E` (CTAP2_ERR_NO_CREDENTIALS).
- The user cancels or cannot unlock: answer `0x27` (CTAP2_ERR_OPERATION_DENIED).

Options: `"up": false` asks for a silent check without user interaction; a
phone authenticator that always asks the user can treat every request as
`"up": true`, but must then not sign silently. `"uv"`: the UV flag may only be
set if the user really verified (unlocked). PassKeyChain ignores the options
and always unlocks, then sets UP and UV.

### getAssertion response

The response is `[status][CBOR]`. The status byte is `0x00` (CTAP2_OK), or an
error code with no CBOR after it. The CBOR map:

| Key | Contents |
|---|---|
| 1 | Credential descriptor `{"id": <credential id>, "type": "public-key"}`: the chosen passkey's id, which (with an allowList) is one of the requested ids |
| 2 | authenticatorData = SHA-256(rpId) ‖ flags (1 byte) ‖ signCount (4 bytes, big-endian) |
| 3 | Signature: DER-encoded ECDSA P-256 over authenticatorData ‖ clientDataHash |
| 4 | User entity `{"id": <user handle bytes>}`: a **map**, not the bare handle (name and displayName may be added). Include it when the allowList was empty: the RP then has no other way to know the account. With an allowList Chrome accepts the response without key 4. **[verified]** |

**Flags:** UP (`0x01`) | UV (`0x04`) | BE (`0x08`), plus BS (`0x10`) while a
copy of the passkey exists elsewhere. Passkeys imported from Bitwarden send
`0x1D`; a passkey created on the phone sends `0x0D` until it has been
exported, `0x1D` afterwards. See [quirk O](#14-quirks-and-gotchas) for why BE
must never change.

**signCount:** PassKeyChain sends the counter stored with the passkey,
unchanged (0 for Bitwarden passkeys). A counter that increases would have to
be stored and would clash with the copy of the same passkey in Bitwarden, so
an imported passkey with counter 0 keeps sending 0, which RPs accept as "no
counter".

The response is encrypted with k2 at the current send nonce and sent as a raw
WebSocket payload. Do not prepend a MessageType byte and do not prepend a
length prefix. The CTAP2 status byte is the first byte of the plaintext.
**[verified]**

### getInfo (0x04)

Answer `[0x00] || the same getInfo CBOR as in the post-handshake message`.
Chrome normally uses the post-handshake copy and does not ask. **[spec]**

### makeCredential (0x01)

Chrome sometimes sends a makeCredential with the dummy rpId `.dummy` (see
[quirk Q](#14-quirks-and-gotchas)). Never create a credential for it: answer
with a single status byte `0x2E` (NO_CREDENTIALS), a 1-byte plaintext
encrypted normally, and keep reading: the real request follows. **[verified
for the probe]**

A real makeCredential (QR hint `"mc"`) creates a passkey. The CBOR map
contains **[spec]**:

| Key | Contents |
|---|---|
| 1 | clientDataHash (32 bytes) |
| 2 | rp: `{"id": string, "name": string}` |
| 3 | user: `{"id": bytes, "name": string, "displayName": string}` |
| 4 | pubKeyCredParams, e.g. `[{"alg": -7, "type": "public-key"}]` |
| 5 | excludeList (credential descriptors the account already has), optional |
| 7 | options, e.g. `{"rk": true}` |

The phone:

- answers `0x26` (UNSUPPORTED_ALGORITHM) if alg -7 (ES256) is not offered;
- answers `0x19` (CREDENTIAL_EXCLUDED) if it holds a credential from the
  excludeList for that rpId;
- otherwise asks the user (and unlocks), generates a P-256 key and a random
  16-byte credential id, **stores** the passkey, and only then answers (`0x27`
  if the user refuses).

Response, "none" attestation **[spec]**:

```text
{1: "none", 2: authenticatorData, 3: {}}

authenticatorData = SHA-256(rpId) || flags || signCount (4 bytes, 0)
                    || aaguid (16 bytes, zeros)
                    || credential id length (2 bytes, big-endian) || credential id
                    || COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y}

flags = UP | UV | AT (0x40) | BE = 0x4D
```

BS stays clear: the new passkey exists only on this phone until it is
exported; its later assertions send BE without BS (`0x0D`) until then, and
`0x1D` afterwards. BE never changes.

**[verified]** against Chrome: a passkey created this way on webauthn.io
registered, and a later sign-in with it was accepted. Unit tests check the
encoding and that an assertion verifies against the attested key.

## 10. Padding and framing summary

Three layers, applied in order to outgoing data:

1. **Application (CBOR map):** EncodePaddedCBORMap, to a 512-byte multiple
   with the uint16_le padding length in the last 2 bytes. Only for the
   post-handshake message.
2. **Transport:** Crypter::Encrypt padding, to a 32-byte multiple with the
   uint8 padding length in the last byte. Applied to every transport message
   (post-handshake, CTAP2 requests from Chrome, CTAP2 responses from the
   phone).
3. **WebSocket framing:** the WebSocket protocol frames the messages. No
   additional length prefix.

The phone's receive side strips the transport padding:

- Decrypt with k1 and the receive nonce.
- Remove the Crypter padding: last byte = N, drop N zero bytes and the length
  byte. Reject the message if N + 1 exceeds its length.
- (EncodePaddedCBORMap padding only occurs on the post-handshake message,
  which the phone sends but never receives.)

Applying an extra 2-byte length prefix before the WebSocket send shifts the
ciphertext and breaks AEAD. This was a real bug during development.

## 11. Nonce construction

Transport nonces are 12 bytes **[verified]**:

| Bytes | Contents |
|---|---|
| 0–7 | All zero |
| 8–11 | The counter, 32-bit **big-endian** |

The counter starts at 0 and increments by 1 per message in each direction,
with separate counters for sending and receiving. It must not pass
`kMaxSequence` (2^24 − 1); a session never comes near that.

The counter is **not** placed in the first 8 bytes little-endian. That was a
real bug: the post-handshake message worked because its counter was 0, and the
getAssertion response failed because its counter was 1 and the two schemes
disagreed.

Handshake-phase AEAD: every MixKey resets the handshake nonce to 0, and in this
handshake each key is used for exactly one AEAD operation (tag1, then tag2).
So the handshake nonce is always 12 zero bytes, and where its counter would go
makes no difference. (PassKeyChain puts it big-endian in bytes 0–3;
**[unverified]** whether Chromium uses the same position.)

## 12. MessageType byte

Chromium's `v2_constants.h` defines **[chromium]**:

| Name | Value |
|---|---|
| kCTAP | `0x00` |
| kJSON | `0x01` |
| kShutdown | `0x02` |
| kUpdate | `0x03` |

Observed behaviour against Chrome **[verified]**:

- The CTAP2 getAssertion request (`0x02`) is sent **without** a MessageType
  prefix. The first byte of the plaintext is `0x02`, then CBOR.
- In some runs an earlier makeCredential probe was sent **with** a MessageType
  prefix `0x00`, followed by `0x01` (makeCredential), then CBOR.
- The phone's CTAP2 response must **not** have a MessageType prefix. Its first
  byte is the CTAP2 status byte (`0x00` for success). Prepending `0x00` causes
  "Trailing data bytes are not allowed" from Chrome's CTAP2 parser.
- A 1-byte message `0x02` means kShutdown (Chrome asks to close the tunnel).
- A 1-byte message `0x03` means kUpdate (Chrome sends update info).

**[unverified]** Whether Chrome adds the prefix probably depends on what was
negotiated (the features in the post-handshake message), not on chance. Until
the rule is known, the receive dispatcher has to recognise both forms:

| Message | Treatment |
|---|---|
| `[0x00][cmd 0x01–0x04][CBOR]` | Strip the prefix, treat as CTAP2 |
| `[cmd 0x01–0x04][CBOR map start 0xA0–0xBF]` | Treat as CTAP2 |
| The single byte `0x04` | CTAP2 getInfo |
| The single byte `0x02` | kShutdown |
| The single byte `0x03` | kUpdate (ignore) |
| Anything else | Ignore |

Note the ambiguity this heuristic has to live with: one byte `0x02` is
kShutdown, not a getAssertion (which always has parameters).

The send path sends `[status][CBOR]` with no prefix.

## 13. Canonical CBOR ordering

Chrome's CTAP2 parser enforces CTAP2 canonical CBOR: map keys must be sorted
by the length of their **encoded** form first, then bytewise. **[spec,
verified]** So integer keys 0–23 come before 1-character strings, and negative
integers sort after positive ones of the same encoded length.

This matters for the getInfo options map: `{"uv": true, "rk": true}` is
rejected, because both keys encode to 3 bytes and `"rk"` < `"uv"`, so `"rk"`
must come first. Use `{"rk": true, "uv": true}`.

Rather than ordering maps by hand, let the encoder sort them. PassKeyChain's
`Cbor.encode` does.

## 14. Quirks and gotchas

- **A.** The tunnel URL paths differ: `/cable/new/` for the phone,
  `/cable/connect/` for Chrome. Using the same path produces a WebSocket that
  never pairs.
- **B.** The header `Sec-WebSocket-Protocol: fido.cable` is required. Without
  it the server returns 400 Bad Request.
- **C.** The psk salt is the 16-byte EID plaintext, not empty. If you derive
  the psk with an empty salt, msg1 fails.
- **D.** The psk is derived from the plaintext you actually advertise. Do not
  generate one plaintext, derive from it, then advertise a different one.
- **E.** The KNpsk0 pattern with prologue `0x01` is what Chrome uses for
  QR-initiated transactions. NKpsk0 with prologue `0x00` is for state-assisted
  transactions and will not work with Chrome's QR flow.
- **F.** Processing an `e` token is `MixHash(e)` **and** `MixKey(e)`, in msg1
  and in msg2. This is the standard Noise rule for handshakes with a PSK, easy
  to overlook when implementing from the basic pattern tables.
- **G.** msg2 must include `MixKey(se) = MixKey(ECDH(ephR_priv,
  peerIdentity65))`. Missing it produces "Invalid caBLE handshake message".
- **H.** Transport keys follow Noise Split: the phone receives with the first
  key and sends with the second. Getting this backwards produces "decryption
  failed for caBLE post-handshake message".
- **I.** Two padding layers for the post-handshake message: EncodePaddedCBORMap
  to 512 bytes with a uint16_le trailer, then Crypter padding to 32 bytes with
  a uint8 trailer. Both are required.
- **J.** No length prefix on WebSocket transport records: the WebSocket frames
  them.
- **K.** The transport nonce counter is 32-bit big-endian in the last 4 bytes
  of a 12-byte nonce, with the first 8 bytes zero. Getting this backwards
  produces a working post-handshake (counter 0) and a failing getAssertion
  response (counter 1).
- **L.** The CTAP2 response must not have a MessageType prefix. The first byte
  is the CTAP2 status byte.
- **M.** The credential id in the response is the id of the passkey that
  signed. With an allowList it is therefore one of the requested ids; if no
  stored passkey's id is in the allowList, do not sign with another one:
  answer `0x2E`.
- **N.** The getInfo options map must be ordered `"rk"` before `"uv"` for
  canonical CBOR.
- **O.** BE ("backup eligible") is a property of the credential that must never
  change: WebAuthn Level 3 lets an RP reject an assertion whose BE differs
  from registration **[spec]**. Bitwarden creates its passkeys with BE=1 and
  BS=1, and a copy stays in Bitwarden, so for imported passkeys `0x1D`
  (UP|UV|BE|BS) is the correct value. Do not switch to `0x05`. UV may only be
  set because the phone really unlocks before signing.
- **P.** "Linking information was not received from caBLE device" is an
  informational log from Chrome. It appears on every run and does not indicate
  a problem. Implementing the linking message is optional and enables re-use
  of the tunnel without a fresh QR.
- **Q.** The makeCredential probe with the dummy rpId `.dummy` does not appear
  on a clean first-time connection. It appears on retries. Reply to it with
  `0x2E` (NO_CREDENTIALS).
- **R.** Chrome's FIDO logging in release builds drops `FIDO_LOG(DEBUG)`.
  Rejection reasons such as "Invalid caBLE handshake message" may not appear
  in logcat even when they are the cause. The presence or absence of an error
  line is not a reliable signal; the successful progression
  (`kCableV2Connected`, "established v2.0") is.
- **S.** Command `0x04` is authenticatorGetInfo and comes without parameters,
  as a single byte; authenticatorSelection is `0x0B`.

## 15. Security requirements

Interoperating is not enough; these make the flow safe.

- **Always advertise over BLE**, never skip it, and never offer a mode without
  it. The proximity check is what stops an attacker who relays the QR from a
  phishing page to a victim somewhere else: without a nearby advert, Chrome
  never connects.
- **The phone cannot check the origin.** It signs for the rpId that Chrome
  sends; it is Chrome that checks the rpId against the page. Show the rpId
  (and the account) to the user before signing, so the user can see what is
  being approved.
- **Ask the user (unlock) for every signature;** sign nothing before the
  request has arrived and the user has chosen and unlocked. The same for
  creating a passkey: show the site and account, unlock, then create.
- **Reject the browser's ephemeral key** if it is not a point on P-256, before
  using it in ECDH.
- **Reject stale QR codes** using QR field 3 (the time), allowing for clock
  differences between computer and phone. (PassKeyChain refuses codes older
  than 20 minutes.)
- **Use fresh randomness** for the EID nonce and the ephemeral key on every
  sign-in.
- **Never log key material** (QR secret, psk, h/ck/k, transport keys) in
  production builds. The debugging checklist below needs those values; keep
  such logging behind a debug-only switch.
- **Time out:** stop advertising and close the tunnel when nothing happens for
  a few minutes, and stop advertising as soon as the handshake is done.

## 16. Debugging checklist

**If Chrome never connects (no msg1 at all):**

- Verify the advert is AES-256-ECB with the full 32-byte aesKey, and the
  4-byte tag is HMAC-SHA256 with hmacKey over the ciphertext.
- Verify the routing ID in the plaintext is the one from this connection's
  `X-Cable-Routing-Id`.
- Verify the BLE advert is actually being broadcast (Bluetooth on, the "Nearby
  devices" permission granted).

**If msg1 fails to decrypt:**

- Verify psk is `HKDF(QRsecret, salt=eidPlaintext, info=[3,0,0,0], 32)`.
- Verify eidPlaintext is exactly what was encrypted and advertised.
- Verify peerIdentity65 is the correct decompression of the QR key.
- Verify the protocol is KNpsk0 with prologue `0x01` (for the QR flow).
- Verify h after `MixHash([0x01])` equals `SHA256(init_h || [0x01])`.
- Verify ck after MixKeyAndHash matches an independent `HKDF-96(psk, ck)`.
- Verify `MixKey(e_pub_i)` follows `MixHash(e_pub_i)`.

**If msg1 works but msg2 is rejected:**

- Verify `MixKey(e_pub_r)` is present.
- Verify `MixKey(ee)` is present.
- Verify `MixKey(se)` is present (ECDH against peerIdentity65).
- Verify EncryptAndHash uses the empty plaintext.

**If msg2 works but the post-handshake message is rejected:**

- Verify the send key is the second Split key, the receive key the first.
- Verify both padding layers (EncodePaddedCBORMap, then Crypter).
- Verify there is no length prefix on the WebSocket send.
- Verify the getInfo maps are in canonical order.

**If the post-handshake message works but the CTAP2 response is rejected:**

- Verify the transport nonce is big-endian in bytes 8–11.
- Verify the response has no MessageType prefix.
- Verify the response maps are in canonical order.
- Verify key 4, if present, is a map `{"id": ...}`, not bare bytes.

**If the RP rejects the signature:**

- Verify the passkey used for signing matches the credential id in the
  response, and that its rpId equals the request's rpId.
- Verify authenticatorData starts with SHA-256 of the rpId, and the signature
  covers authenticatorData ‖ clientDataHash.
- Verify the BE flag matches what the credential had at registration.

## 17. Reference: constants

From Chromium's `v2_constants.h` and related code **[chromium]**:

| Name | Value | Unit | Notes |
|---|---|---|---|
| kNonceSize | 10 | bytes | The random part of the EID plaintext |
| kRoutingIdSize | 3 | bytes | |
| kTunnelIdSize | 16 | bytes | (128 bits) |
| kP256X962Length | 65 | bytes | Uncompressed P-256 point |
| kCompressedPublicKeySize | 33 | bytes | |
| kEIDKeySize | 64 | bytes | AES-256 key (32) ‖ HMAC key (32) |
| kPSKSize | 32 | bytes | |
| kAdvertSize | 20 | bytes | 16-byte AES block + 4-byte HMAC tag |
| kPostHandshakeMsgPaddingGranularity | 512 | bytes | |
| kPaddingGranularity | 32 | bytes | Crypter transport padding |
| kMaxSequence | 2^24 − 1 | messages | Nonce counter limit (a count, not a size) |

| Item | Value |
|---|---|
| Service UUID | `0000FFF9-0000-1000-8000-00805F9B34FB` |
| Tunnel server domains | `cable.ua5v.com` (0, Google), `cable.auth.com` (1, Apple); 256–65535 computed |
| WebSocket subprotocol | `fido.cable` |
| Protocol name | `Noise_KNpsk0_P256_AESGCM_SHA256` |
| Prologue | `0x01` |
| Cipher suite | AES-256-GCM, SHA-256, P-256 ECDH |
| EID cipher | AES-256-ECB (one block) + truncated HMAC-SHA256 |
| CTAP2 commands | `0x01` makeCredential, `0x02` getAssertion, `0x04` getInfo, `0x0B` selection |
| CTAP2 status | `0x00` OK, `0x01` invalid command, `0x12` invalid CBOR, `0x19` credential excluded, `0x26` unsupported algorithm, `0x27` operation denied, `0x2E` no credentials |

## 18. Test vectors

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

```text
CBOR     a6005821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed0150000102030405060708090a0b0c0d0e0f0202031a6af0563004f405626761
QR text  FIDO:/064761326369506941132196635817367045715076129656615309261485932746823659474011834762800564050807352788025421010491811870057950297627316213606389454340866107096654083076
```

### 18.2 Keys from the QR secret

[Section 3](#3-key-derivation-from-the-qr-secret):

```text
EID AES key   d06e92859fa9afce38139c04dae7f64196acfdb9a28dffb326f3a8f2cc0788e2
EID HMAC key  28bd73c3484f2f7de169d9b087c30e6f409e70bc86f5d65e03d762b4b0df2af7
tunnel id     de1d8150b45f03349b2b00a52e2e893e
```

The phone connects to `wss://cable.ua5v.com/cable/new/de1d8150b45f03349b2b00a52e2e893e`.

### 18.3 Advert and PSK

[Section 5](#5-ble-advertisement-eid), with nonce `a0 a1 .. a9`, routing id `c0ffee`:

```text
EID plaintext (domain 0)    00a0a1a2a3a4a5a6a7a8a9c0ffee0000
advert (domain 0)           94198c8ba6d8f263ce372e5a84b41f31e66db611
EID plaintext (domain 266)  00a0a1a2a3a4a5a6a7a8a9c0ffee0a01
advert (domain 266)         783741baf316f77f3770a0e3e4384f0160c177f9
psk (domain 0 plaintext)    7cc9adc8f8a4663be4c0e4cda5b44a9c38369d5309e73b6b446d3096f551641d
```

Domain 266 is the computed server `cable.wufkweyy3uaxb.com` ([section 4](#4-tunnel-server-websocket-setup)); its
number appears little-endian in bytes 14–15 (`0a01`), and it changes the
advert and the psk.

### 18.4 Noise handshake

[Section 6](#6-noise-handshake), with the fixed keys above and, so that this
vector stands on its own, the psk `00 01 .. 1f` rather than the one from 18.3:

```text
s_i (uncompressed)                           040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794
e_i                                          04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285
e_r                                          0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a1
psk                                          000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
h = ck after init (name padded to 32 bytes)  4e6f6973655f4b4e70736b305f503235365f41455347434d5f53484132353600
h after MixHash(prologue 0x01)               2368ca317a7b06a2424e87c2705aea6823e02b9aff3755ee08a0bc3ad49e10ac
h after MixHash(s_i, uncompressed)           e5f19b46d787fc4c5226d7df6615b0c59a9530957f5fc5585eb2130df9399da1
ck after MixKeyAndHash(psk)                  7f820705cec698399d00b7cc8884a0ef064bdc1135a59aad002049fa02e1384d
h after MixKeyAndHash(psk)                   f78be16cd56481d19b2da266fdc8ec317e9082669cbb0babb3cd49226bef5872
h after msg1                                 da6897087c09337f2d616c693d757379f7f82fe5c0e211b1cf0c197ac9f0e09d
```

```text
msg1 (browser)  04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c912850b5cdd7aad2f31288946b97b9bf4ff30
msg2 (phone)    0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a10bbf8dd558164c71c16b2efd758a64b3
handshake hash  5279b5a75e774b9db7607132ca0695a87db5b54aa922ab897b536168f5dce415
```

### 18.5 Transport

[Sections 7, 10 and 11](#7-transport-keys): `k1` the phone receives with, `k2`
it sends with; every record is Crypter-padded to 32 bytes and sealed with
AES-256-GCM, no additional data, nonce `00`×8 ‖ counter (big-endian).

```text
k1 (browser -> phone)          c736eed4e03cdfd00c86ed2315762dcf191196e7de0d9e000cd02c40d5043934
k2 (phone -> browser)          d96ef52dcaf9deb0e52e8c08d5cca5793fcd2d9ed509f5be27974c8573e9467c
nonce, counter 1               000000000000000000000001
phone sends 00a0, counter 0    711ee11d8f612de52bfffbe608bfd0ba02179546c6612e8cf46f2fb412caade1e17b0ff77d7f0de4a5ec2551c2f9d2dd
phone sends 'x'*40, counter 1  cefab81e86b9b90afc1d09e693f16f4c2e429c7e2711b1c13e277926a38f1d3b3d8eb6f5949a3d48b1b871cbe1db24027a3fb81a6db234bdb2302a53c3a91482fbce1db6256440fb3b4748717eee1cdd
phone receives, counter 0      e6d80410f66e95b9d5b8a4388bd9db846fab9a36fee839a1d7345f64bf3240eda18c96d881084ca73a200c2b58af36dd
... which opens to             02a1016161
```

Post-handshake padding: a 100-byte CBOR map is padded to 512 bytes, ending in
`9a01` (410 padding bytes, little-endian); a 511-byte map to 1024.

### 18.6 Tunnel server names

[Section 4](#4-tunnel-server-websocket-setup):

```text
256    cable.qz2ekwmnd332c.info
266    cable.wufkweyy3uaxb.com   (Chromium's test value)
65535  cable.lw6vahpb5pldb.net
```
