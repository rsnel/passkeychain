caBLE v2 (Hybrid Transport) — Complete Protocol Notes
======================================================

This document records everything needed to implement a working caBLE v2
authenticator (phone side, responder) that interoperates with Chrome on the
desktop as the initiator. It was derived from Chromium source
(device/fido/cable/*, especially v2_handshake.cc, noise.cc,
v2_authenticator.cc, fido_tunnel_device.cc), from live logs of a working
implementation, and from offline verification of the cryptographic steps.

Every value below has been observed to work against Chrome. Where the
protocol has quirks that are not in the FIDO specification, they are called
out explicitly.

Contents
--------
1.   Roles and overall flow
2.   QR code contents
3.   Key derivation from the QR secret
4.   Tunnel server WebSocket setup
5.   BLE advertisement (EID)
6.   Noise handshake: pattern, init, msg1, msg2
7.   Transport keys
8.   Post-handshake message
9.   CTAP2 exchange over the tunnel
10.  Padding and framing summary
11.  Nonce construction
12.  MessageType byte
13.  Canonical CBOR ordering
14.  Quirks and gotchas
15.  Debugging checklist
16.  Reference: v2_constants.h values

======================================================
1. ROLES AND OVERALL FLOW
======================================================

Desktop (Chrome) is the INITIATOR. Phone (authenticator) is the RESPONDER.

Flow:

  a. Chrome shows a QR code.
  b. Phone scans the QR, parses the CBOR payload, and derives keys.
  c. Phone connects to the tunnel server at /cable/new/<tunnelId>.
  d. Tunnel server returns a 3-byte routing ID in the response header
     X-Cable-Routing-Id.
  e. Phone builds an EID (encrypted BLE advertisement) with that routing ID,
     encrypts it, and advertises it over BLE on service UUID 0xFFF9.
  f. Chrome scans BLE, decrypts the EID, learns the routing ID and tunnelId,
     and connects to /cable/connect/<routingId>/<tunnelId>.
  g. The tunnel server pairs the two WebSocket connections.
  h. Chrome sends Noise handshake message 1 (msg1).
  i. Phone decrypts msg1, builds msg2, sends it.
  j. Chrome accepts msg2, derives transport keys.
  k. Phone sends the post-handshake message (features + getInfo).
  l. Chrome accepts the post-handshake message.
  m. Chrome sends a CTAP2 getAssertion or makeCredential.
  n. Phone signs and returns the CTAP2 response.
  o. Chrome closes the tunnel; the RP verifies the assertion.

The phone must connect to /cable/new/ BEFORE advertising BLE, because the
routing ID in the EID comes from the tunnel server's response headers and
Chrome will not connect to /cable/connect/ until it sees the EID.

======================================================
2. QR CODE CONTENTS
======================================================

The QR is a "FIDO:/" string followed by decimal digits. The digits decode
to a CBOR map with these keys:

  0: compressed P-256 public key (33 bytes, prefix 0x02 or 0x03)
  1: QR secret (16 bytes)
  2: number of known tunnel server domains (integer)
  3: current unix time (integer, seconds)
  4: supports linking / state-assisted (boolean)
  5: request hint: "ga" (getAssertion) or "mc" (makeCredential)

The public key in field 0 is the DESKTOP's static public key, not the
phone's. The QR secret in field 1 is the input to all key derivation.

Digit encoding: chunks of 7 bytes are encoded as 17 decimal digits,
little-endian. The chunk widths are {3,5,8,10,13,15,17} digits for
{1,2,3,4,5,6,7} bytes.

======================================================
3. KEY DERIVATION FROM THE QR SECRET
======================================================

All derivations use HKDF-SHA256 with an EMPTY salt unless noted. "info" is a
4-byte LITTLE-ENDIAN integer label.

  QR secret = the 16 bytes from QR field 1.

  EID AES key and EID HMAC key:
    material = HKDF(ikm=QRsecret, salt=empty, info=[1,0,0,0], len=64)
    aesKey   = material[0..32]
    hmacKey  = material[32..64]

  tunnelId (used in the tunnel server URL):
    tunnelId = HKDF(ikm=QRsecret, salt=empty, info=[2,0,0,0], len=16)

  Noise PSK:
    psk = HKDF(ikm=QRsecret, salt=eidPlaintext, info=[3,0,0,0], len=32)
    where eidPlaintext is the full 16-byte EID plaintext (see section 5).
    NOTE THE SALT: the 16-byte EID plaintext, not empty.

The tunnelId derivation is confirmed correct: it matches the tunnelId Chrome
prints in its own /cable/connect/<routing>/<tunnelId> URL, character for
character, for the same QR.

The psk derivation is confirmed correct by offline HKDF computation against
the value the app logs and uses.

======================================================
4. TUNNEL SERVER WEBSOCKET SETUP
======================================================

URL for the phone: wss://cable.ua5v.com/cable/new/<hex(tunnelId)>
URL for Chrome:    wss://cable.ua5v.com/cable/connect/<hex(routingId)>/<hex(tunnelId)>

The tunnelId is lowercase hex, no dashes. The routingId is the 3-byte value
the server assigns (also lowercase hex, 6 characters).

WebSocket upgrade:

  - Send header Sec-WebSocket-Protocol: fido.cable
    WITHOUT THIS the server returns "400 Bad Request".
  - The successful response contains a header X-Cable-Routing-Id with the
    3-byte routing ID (hex).

IMPORTANT: the phone and Chrome connect to DIFFERENT paths. The phone uses
/cable/new/, Chrome uses /cable/connect/. Using /cable/connect/ from the
phone returns a WebSocket that never gets paired.

The routing ID is NOT used in the phone's own /cable/new/ URL. It is only
used (a) in the EID plaintext, and (b) by Chrome in its /cable/connect/ URL.

======================================================
5. BLE ADVERTISEMENT (EID)
======================================================

Service UUID: 0000FFF9-0000-1000-8000-00805F9B34FB

The EID plaintext is 16 bytes:

  byte 0:      0x00
  bytes 1-10:  10-byte nonce (kNonceSize = 10)
  bytes 11-13: 3-byte routing ID from X-Cable-Routing-Id
  bytes 14-15: 2-byte tunnel server domain, BIG-ENDIAN (0 for cable.ua5v.com)

The 20-byte BLE payload:

  ciphertext = AES-128-ECB-encrypt(eidPlaintext, aesKey)   (16 bytes)
  tag        = HMAC-SHA256(ciphertext, hmacKey)[0..4]      (4 bytes)
  payload    = ciphertext || tag                           (20 bytes)

The AES key is 32 bytes because the material is 64 bytes split in half; in
practice only the first 16 bytes of aesKey are used by AES-128-ECB, and the
remaining 16 bytes are ignored by the cipher but are still part of the key
material derivation. (Some implementations use AES-256 on the 16-byte
plaintext padded out; the working implementation uses AES-128 with the first
16 bytes.)

Chrome decrypts this, validates the HMAC, and extracts the routing ID from
the plaintext. The 10-byte nonce is not used in the handshake; it is used as
part of the salt for the psk derivation, so it must be exactly the bytes
Chrome decrypts from your advertisement.

The plaintext you use for the psk derivation MUST be the same bytes you
encrypt into the advertisement. If you build one and encrypt another, the
psk will not match and msg1 will fail to decrypt.

======================================================
6. NOISE HANDSHAKE
======================================================

Protocol name: "Noise_KNpsk0_P256_AESGCM_SHA256"

The pattern observed to work against Chrome for QR-initiated transactions is
KNpsk0 with prologue 0x01. This is not the only pattern in Chromium's code;
NKpsk0 with prologue 0x00 exists for state-assisted transactions. The
desktop's QR-initiated flow uses KNpsk0.

Chromium's BuildInitialMessage selects the pattern based on peer_identity_:
  - peer_identity_ set, no local identity: NKpsk0, prologue 0x00
  - no peer_identity_, local identity:   KNpsk0, prologue 0x01

For the QR flow the desktop has a local identity (its own keypair whose
public half is in the QR) and no peer_identity_, so it uses KNpsk0. The
phone, as responder, mirrors this.

Proceed as follows.

--- INITIALISATION (responder) ---

  ck = 32 zero bytes
  ck[0..len(protocolName)] = protocolName   (31 bytes; one zero byte pad)
  h = ck

  MixHash([0x01])                 // prologue, single byte 0x01
  MixHash(peerIdentity65)         // the QR's 65-byte uncompressed public key
  MixKeyAndHash(psk)              // 32-byte psk

  peerIdentity65 is the decompression of the 33-byte QR public key to
  65-byte uncompressed P-256 (0x04 || X || Y). If the QR key starts with
  0x02 choose even Y, if 0x03 choose odd Y.

--- MSG1 (from Chrome, 81 bytes = e_pub 65 + tag 16) ---

  MixHash(e_pub_i)                // 65 bytes, uncompressed P-256
  MixKey(e_pub_i)                 // MixKey, not just MixHash
  plaintext = DecryptAndHash(tag1)   // must be empty

  If DecryptAndHash throws, the psk or the initial h/ck chain is wrong.
  If it succeeds and the plaintext is empty, msg1 is correctly processed.

--- MSG2 (from phone, 81 bytes = e_pub 65 + tag 16) ---

Generate a fresh P-256 ephemeral keypair ephR.

  MixHash(e_pub_r)                // 65 bytes, uncompressed P-256
  MixKey(e_pub_r)                 // MixKey of the ephemeral point
  ee = ECDH(ephR_priv, e_pub_i)
  MixKey(ee)
  se = ECDH(ephR_priv, peerIdentity65)   // ECDH against the QR's static key
  MixKey(se)                             // present in KNpsk0, absent in NKpsk0
  tag2 = EncryptAndHash(empty)           // 16-byte AEAD tag
  msg2 = e_pub_r || tag2

The se step is the one most commonly missed. Chromium's RespondToHandshake
for the KNpsk0 branch does, in order:
  MixHash(peer_point_bytes)
  MixKey(peer_point_bytes)
  MixKey(shared_key_ee)
  if (peer_identity) MixKey(shared_key_se)
  EncryptAndHash({})

Missing se makes msg2 fail with "Invalid caBLE handshake message" (the
AEAD tag verifies against a different k than Chrome's).

--- No further handshake messages ---

After msg2 the handshake is complete. The transport keys are derived (see
section 7) and the post-handshake message is sent (section 8).

======================================================
7. TRANSPORT KEYS
======================================================

After msg2:

  (first32, second32) = HKDF2(ck, empty)
    where HKDF2(ck, ikm) = HKDF(ikm, salt=ck, info=empty, len=64),
    split into two 32-byte halves.

  read_key  = first32
  write_key = second32

Assign as follows:

  phone's txKey (what it uses to encrypt messages to Chrome) = write_key
  phone's rxKey (what it uses to decrypt messages from Chrome) = read_key

The variable names "read_key" and "write_key" are from the responder's
perspective in Chromium's Crypter (read_key_ decrypts, write_key_ encrypts).
From the initiator's (Chrome's) perspective the roles are reversed, so
Chrome's write_key equals the phone's read_key and vice versa.

Getting this backwards produces "decryption failed for caBLE
post-handshake message" even though the handshake and msg2 were accepted.

======================================================
8. POST-HANDSHAKE MESSAGE
======================================================

After msg2 the phone sends a CBOR map with its features and a getInfo
response. Chrome will not send the CTAP2 request until it receives this.

CBOR map (top level):
  key 1: getInfo response, as a CBOR byte string
  key 3: features array, e.g. ["ctap"]

getInfo response (nested CBOR map):
  key 1: versions, e.g. ["FIDO_2_0", "FIDO_2_1"]
  key 2: extensions, e.g. ["prf"]
  key 3: aaguid, 16 bytes (zeros acceptable)
  key 4: options, {"rk": true, "uv": true}
         NOTE ORDER: canonical CBOR requires "rk" before "uv" (both 2 bytes,
         "rk" < "uv" lexically). Chrome's CTAP2 parser rejects the reversed
         order with a "Map keys must be strictly monotonically increasing"
         error.
  key 9: transports, e.g. ["cable", "hybrid", "internal"]

Two padding layers are applied before encryption:

  Layer A — EncodePaddedCBORMap (application layer):
    - Encode the CBOR map to bytes: L bytes.
    - padded_size = round_up(L + 2, 512)
    - num_padding = padded_size - L - 2
    - padded = CBOR || num_padding zero bytes || uint16_le(num_padding)

  Layer B — Crypter::Encrypt padding (transport layer):
    - padded_size = round_up(len + 1, 32)
    - num_zeros = padded_size - len - 1
    - padded = bytes || num_zeros zero bytes || uint8(num_zeros)

The two layers are separate. Applying only Layer A produces "Invalid
padding in caBLE handshake message". Applying neither produces
"decryption failed for caBLE post-handshake message" (the AEAD key is
correct but Chrome's Crypter sees garbage after decryption).

After Layer B the plaintext is encrypted with txKey and the current
txNonce, and sent as a raw WebSocket payload (no length prefix).

======================================================
9. CTAP2 EXCHANGE OVER THE TUNNEL
======================================================

Chrome sends the CTAP2 request as a raw WebSocket payload, encrypted with
its write_key (your read_key) and a transport nonce.

The decrypted plaintext begins with the CTAP2 command byte:
  0x01 authenticatorMakeCredential
  0x02 authenticatorGetAssertion
  0x04 authenticatorSelection (rare)
followed by CBOR.

There is NO MessageType prefix on CTAP2 requests in the observed flow. The
first byte of the plaintext is the CTAP2 command, not a MessageType. (An
earlier probe makeCredential with a MessageType prefix 0x00 was observed in
some runs, so the receiver must accept both forms; see section 12.)

For a getAssertion (0x02), the CBOR map contains:
  1: rpId (string)
  2: clientDataHash (32 bytes)
  3: allowList (array of {id: bytes, type: "public-key"})
  5: options (e.g. {"uv": true})

The response is [status][CBOR]:

  status byte: 0x00 (CTAP2_OK), or an error code (e.g. 0x2E = NO_CREDENTIALS)
  CBOR map:
    key 1: credential descriptor {id: <requested id>, type: "public-key"}
    key 2: authenticatorData (rpIdHash || flags || signCount)
    key 3: signature (DER-encoded ECDSA over authenticatorData || clientDataHash)
    key 4: user handle — INCLUDE ONLY for discoverable credentials
           (empty allow list); for a non-discoverable getAssertion Chrome
           accepts the response without key 4.

The response's credential id MUST be the id Chrome requested in its allow
list, not the passkey's own stored id. Echoing a different id makes Chrome
treat the response as belonging to a different credential and reject it.
If Chrome's allow list contains an id you have a passkey for, use that
passkey's private key for the signature; if the requested id does not match
the passkey you are using, the RP will reject the signature (Chrome
forwards it unchanged).

The response is encrypted with txKey at the current txNonce and sent as a
raw WebSocket payload. Do not prepend a MessageType byte and do not
prepend a length prefix. The CTAP2 status byte is the first byte of the
plaintext.

The makeCredential probe (0x01) is sent by Chrome only when the tunnel
needs to prove itself; on a clean first connection it is skipped. If it is
sent, reply with a single status byte 0x2E (NO_CREDENTIALS) — the app does
not create credentials. This is a 1-byte plaintext encrypted normally.

======================================================
10. PADDING AND FRAMING SUMMARY
======================================================

Three layers, applied in order to outgoing data:

  1. Application (CBOR map) → EncodePaddedCBORMap → 512-byte multiple with
     uint16_le length in the last 2 bytes. Only for the post-handshake
     message.

  2. Transport → Crypter::Encrypt padding → 32-byte multiple with uint8
     length in the last byte. Applied to every transport message (post-
     handshake, CTAP2 requests from Chrome, CTAP2 responses from the phone).

  3. WebSocket framing: the WebSocket protocol provides message framing.
     No additional length prefix.

The phone's receive side must strip both pads in reverse:

  - Decrypt with rxKey/rxNonce.
  - Remove Crypter padding: last byte = N, drop N zero bytes and the length
    byte.
  - For the post-handshake message only, remove EncodePaddedCBORMap
    padding: last 2 bytes = uint16_le(M), drop M zero bytes and the 2-byte
    length.

Applying an extra 2-byte length prefix before WebSocket send shifts the
ciphertext and breaks AEAD. This was a real bug during development.

======================================================
11. NONCE CONSTRUCTION
======================================================

Transport nonces are 12 bytes:

  bytes 0-7:  all zero
  bytes 8-11: the counter, 32-bit BIG-ENDIAN

Counter starts at 0, increments by 1 per message in each direction.
Separate counters for transmit (tx) and receive (rx).

The counter is NOT placed in the first 8 bytes little-endian. That was a
real bug: the post-handshake message worked because its counter was 0, and
the getAssertion response failed because its counter was 1 and the two
schemes disagreed.

Handshake-phase AEAD uses its own nonce counter, also 12 bytes with the
counter in the low 4 bytes; that counter resets at each MixKey.

======================================================
12. MESSAGE TYPE BYTE
======================================================

Chromium's v2_constants.h defines:

  kCTAP     = 0x00
  kJSON     = 0x01
  kShutdown = 0x02
  kUpdate   = 0x03

Observed behaviour against Chrome:

  - The CTAP2 getAssertion request (0x02) is sent WITHOUT a MessageType
    prefix. First byte of plaintext is 0x02, then CBOR.
  - In some runs an earlier makeCredential probe was sent WITH a
    MessageType prefix 0x00, followed by 0x01 (makeCredential), then CBOR.
  - The phone's CTAP2 response must NOT have a MessageType prefix. First
    byte is the CTAP2 status byte (0x00 for success). Prepending 0x00
    causes "Trailing data bytes are not allowed" from Chrome's CTAP2 parser.
  - A 1-byte message 0x02 means kShutdown (Chrome requesting tunnel close).
  - A 1-byte message 0x03 means kUpdate (Chrome sending update info).

The receive dispatcher should:

  - Accept [0x00][cmd 0x01-0x04][CBOR] → strip prefix, treat as CTAP2.
  - Accept [cmd 0x01-0x04][CBOR map start 0xA0..0xBF] → treat as CTAP2.
  - Treat single byte 0x02 as kShutdown.
  - Treat single byte 0x03 as kUpdate (ignore).
  - Ignore or drop anything else.

The send path should send [status][CBOR] with no prefix.

======================================================
13. CANONICAL CBOR ORDERING
======================================================

Chrome's CTAP2 parser enforces canonical CBOR: map keys must be sorted by
encoded byte length first, then lexicographically.

This matters for the getInfo options map: {"uv": true, "rk": true} is
rejected because both keys are 2 bytes and "rk" < "uv" so "rk" must come
first. Use {"rk": true, "uv": true}.

It also matters for any other map where the keys have different lengths.
The CTAP2 response maps (keys 1, 2, 3, 4 — all 1 byte) are naturally
ordered.

======================================================
14. QUIRKS AND GOTCHAS
======================================================

A. The tunnel URL paths differ. /cable/new/ for the phone, /cable/connect/
   for Chrome. Using the same path produces a WebSocket that never pairs.

B. The Sec-WebSocket-Protocol header "fido.cable" is required. Without it
   the server returns 400 Bad Request.

C. The psk salt is the 16-byte EID plaintext, not empty. If you derive the
   psk with an empty salt, msg1 fails.

D. The psk is derived from the plaintext you actually advertise. Do not
   generate one plaintext, derive from it, then advertise a different one.

E. The KNpsk0 pattern with prologue 0x01 is what Chrome uses for
   QR-initiated transactions. NKpsk0 with prologue 0x00 is for
   state-assisted transactions and will not work with Chrome's QR flow.

F. msg1 processing uses MixKey(e_pub_i) in addition to MixHash(e_pub_i).
   This is not part of standard Noise; Chromium does it.

G. msg2 must include MixKey(se) = MixKey(ECDH(ephR_priv, peerIdentity65)).
   Missing this produces "Invalid caBLE handshake message".

H. Transport keys are (read, write) in that order. The phone's txKey is
   write, rxKey is read. Getting this backwards produces "decryption
   failed for caBLE post-handshake message".

I. Two padding layers for the post-handshake message: EncodePaddedCBORMap
   to 512 bytes with a uint16_le trailer, then Crypter padding to 32 bytes
   with a uint8 trailer. Both required.

J. No length prefix on WebSocket transport records. The WebSocket frames
   them.

K. Transport nonce counter is 32-bit big-endian in the last 4 bytes of a
   12-byte nonce, with the first 8 bytes zero. Getting this backwards
   produces a working post-handshake (counter 0) and a failing getAssertion
   response (counter 1).

L. The CTAP2 response must not have a MessageType prefix. The first byte
   is the CTAP2 status byte.

M. The response's credential descriptor must echo the id Chrome requested
   in its allow list, not the passkey's stored id.

N. The getInfo options map must be ordered "rk" before "uv" for canonical
   CBOR.

O. The authenticatorData flags default to 0x1D (UP|UV|BE|BS). BE|BS
   declares the credential backup-eligible and currently backed up. For
   an on-device-only passkey this is arguably incorrect; changing to 0x05
   (UP|UV) is a policy decision and affects both the hybrid and on-device
   flows.

P. "Linking information was not received from caBLE device" is an
   informational log from Chrome. It appears on every run and does not
   indicate a problem. Implementing the linking message is optional and
   enables re-use of the tunnel without a fresh QR.

Q. The makeCredential probe with dummy rpId ".dummy" does not appear on a
   clean first-time connection. It appears on retries. Reply to it with
   0x2E (NO_CREDENTIALS).

R. Chrome's FIDO logging in release builds drops FIDO_LOG(DEBUG). Rejection
   reasons such as "Invalid caBLE handshake message" may not appear in
   logcat even when they are the cause. The presence or absence of an error
   line is not a reliable signal; the successful progression
   (kCableV2Connected, established v2.0) is.

======================================================
15. DEBUGGING CHECKLIST
======================================================

If msg1 fails to decrypt:
  - Verify psk is HKDF(QRsecret, salt=eidPlaintext, info=[3,0,0,0], 32).
  - Verify eidPlaintext is exactly what was encrypted and advertised.
  - Verify peerIdentity65 is the correct decompression of the QR key.
  - Verify the protocol is KNpsk0 with prologue 0x01 (for QR flow).
  - Verify h after MixHash([0x01]) equals SHA256(init_h || [0x01]).
  - Verify ck after MixKeyAndHash matches an independent HKDF-96(psk, ck).

If msg1 works but msg2 is rejected:
  - Verify MixKey(e_pub_r) is present.
  - Verify MixKey(ee) is present.
  - Verify MixKey(se) is present (ECDH against peerIdentity65).
  - Verify EncryptAndHash uses the empty plaintext.

If msg2 works but post-handshake is rejected:
  - Verify transport keys are assigned (txKey=write, rxKey=read).
  - Verify both padding layers (EncodePaddedCBORMap then Crypter).
  - Verify no length prefix on WebSocket send.

If post-handshake works but the CTAP2 response is rejected:
  - Verify transport nonce is big-endian in bytes 8-11.
  - Verify the response has no MessageType prefix.
  - Verify the response credential id matches the requested allow-list id.

If the RP rejects the signature:
  - Verify the passkey used for signing matches the credential id Chrome
    requested.

======================================================
16. REFERENCE: v2_constants.h VALUES
======================================================

kNonceSize            = 10       (bytes of nonce in EID plaintext)
kRoutingIdSize        = 3
kTunnelIdSize         = 16
kP256X962Length       = 65       (uncompressed P-256 point)
kCompressedPublicKeySize = 33
kEIDKeySize           = 64       (AES key 32 || HMAC key 32)
kPSKSize              = 32
kAdvertSize           = 20       (16 AES block + 4 HMAC tag)
kPostHandshakeMsgPaddingGranularity = 512
kPaddingGranularity   = 32       (Crypter transport padding)
kMaxSequence          = 2^24 - 1 (nonce counter limit)

Service UUID          = 0000FFF9-0000-1000-8000-00805F9B34FB
Tunnel server domain  = cable.ua5v.com (KnownDomainID 0)
WebSocket subprotocol = "fido.cable"

Protocol name         = "Noise_KNpsk0_P256_AESGCM_SHA256"
Prologue              = 0x01
Cipher suite          = AES-256-GCM, SHA-256, P-256 ECDH

======================================================
END
======================================================