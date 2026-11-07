# PassKeyChain

**Passkey sovereignty:** your passkeys, on a phone you choose, under your
control. An open-source Android app that **imports your FIDO2 passkeys**, stores the
private keys in Android Keystore-encrypted storage, uses them to sign in — on a
computer by scanning its sign-in QR code (the FIDO hybrid transport: Bluetooth
plus an encrypted tunnel), and on the phone itself as a system passkey
provider — and can **export** them again. It keeps itself up to date from
GitHub Releases.

> PassKeyChain manages credentials **you already own**. Keys never leave your
> device; there is no server and no telemetry. Passkey import/export follows the
> FIDO Alliance Credential Exchange direction (2025).

Website / screenshots: **https://rsnel.github.io/passkeychain/**

---

## Status (honest)

**Working and unit-tested** (re-verified in CI on every build):

- Bitwarden import/export round-trip
- P-256 private-key decoding across PEM / base64-PKCS#8 / raw-scalar encodings
- WebAuthn **ES256 assertion signing** (`authenticatorData || clientDataHash`)
- FIDO `FIDO:/` hybrid **QR decoding** (base-10 digit packing + CBOR)
- Keystore-encrypted storage, Jetpack Compose UI, self-update channel logic

**Cross-device sign-in works** (tested end to end against a real Microsoft
sign-in):

- Scanning the computer's `FIDO:/` QR code and deriving the keys
- The Bluetooth (BLE) proximity broadcast
- The Noise-encrypted tunnel through the relay server
- CTAP2 getAssertion over the tunnel, signed with the imported passkey

That is about 1000 lines of Kotlin in `hybrid/`.

**Creating passkeys** on the phone for a site on a computer (the site's
"create a passkey" QR code): works; tested with webauthn.io (register,
then sign in with the new passkey). A new passkey is backup-eligible but not backed up
until it is exported to Bitwarden.

**Activity log**: the last 200 sign-ins (site, account, time, outcome) and
changes (passkeys created, deleted, imported, exported), encrypted on the
phone; "last used" in the passkey details.

---

## Build

No Android Studio needed for a debug build:

```bash
./gradlew assembleDebug           # -> app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest       # runs the crypto verification suite
```

Requirements: JDK 17, Android SDK (platform 35, build-tools 35). CI
(`.github/workflows/build.yml`) does exactly this on every push.

## Builds, signing & self-update

Works like Kaartscan:

- **Every CI build is a debug build** (push or pull request): unit tests +
  `assembleDebug`, APK uploaded as a run artifact.
- **A push to `main`** also replaces the rolling pre-release
  [`debug`](https://github.com/rsnel/passkeychain/releases/tag/debug) with
  `passkeychain-debug.apk` and `passkeychain-debug.json`
  (`{"version", "build", "commit"}`). No per-build tags.
- The **debug app** (`it.snel.passkeychain.debug`, "PassKeyChain debug")
  reads that JSON and offers the APK when its `build` (the CI run number, also
  the APK's `versionCode`) is newer than its own.
- Version names come from `git describe --tags --match 'v*'` (just the commit
  hash until a `v*` tag exists).
- Debug builds are signed with the committed `app/debug.keystore` (standard
  debug credentials), so every debug build installs over the previous one.

**Releases** come from `v*` tags: the version is set by hand in
`AndroidManifest.xml` (CI checks that the tag matches), the APK is signed via
the repository secrets `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`,
`KEY_PASSWORD` (locally: copy `keystore.properties.example` to
`keystore.properties`) and published as a GitHub release, which the release
app follows via `/releases/latest`. Download:
[latest release](https://github.com/rsnel/passkeychain/releases/latest).
The debug app has a grey icon, so the two are easy to tell apart.

## Import and export

- **Bitwarden** JSON exports, unencrypted or password protected (below).
- **Credential Exchange (CXF)** documents: the FIDO Alliance format for moving
  passkeys between managers. *Import passkeys… → From another app* uses Android's
  credential transfer (`androidx.credentials.providerevents`, beta) to fetch
  them from another manager on the phone that offers it; a CXF file can be
  imported like a Bitwarden file.
- **Export** writes Bitwarden's format (optionally password protected).
  PassKeyChain does not offer its passkeys to *other apps* through Android's
  credential transfer: that would hand every private key to another app
  through an API still in beta, guarded by checks each app has to get right
  itself. An export file you make and move yourself keeps that decision
  with you.

## Import format

PassKeyChain reads and writes Bitwarden's unencrypted JSON export
(Bitwarden: *Tools → Export vault → File format: .json*). Passkeys sit inside
login items:

```json
{ "encrypted": false, "items": [ { "type": 1, "name": "Microsoft", "login": {
    "username": "...", "fido2Credentials": [ {
      "credentialId": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
      "keyType": "public-key", "keyAlgorithm": "ECDSA", "keyCurve": "P-256",
      "keyValue": "<PKCS#8 private key, base64url>",
      "rpId": "login.microsoft.com", "userHandle": "<base64url>",
      "userName": "...", "counter": "0", "rpName": "Microsoft",
      "userDisplayName": "...", "discoverable": "true",
      "creationDate": "2026-09-16T06:32:48.156Z" } ] } } ] }
```

- `credentialId` is a GUID for 16-byte credential ids, otherwise `b64.` +
  base64url (Bitwarden's convention).
- The importer finds every `fido2Credentials` array anywhere in the file, so a
  full export, one item or just the pasted array all work. Other items
  (passwords, notes) are ignored.
- `keyValue` is also accepted as PEM or base64 PKCS#8 (older PassKeyChain
  exports).
- Export writes the same structure, so Bitwarden can import it again.

A throwaway example (dummy key) is at [`docs/sample-passkey.json`](docs/sample-passkey.json).

**Encrypted backups.** PassKeyChain reads and writes Bitwarden's
*password protected* encrypted export (Bitwarden: Export vault → .json
(Encrypted) → Password protected), so passkeys never have to exist as a plain
file. The password goes through PBKDF2-SHA256 (600,000 iterations when
PassKeyChain exports; files from Bitwarden may also use Argon2id, implemented
in pure Kotlin), is stretched with HKDF into an AES-256-CBC key and an
HMAC-SHA256 key, and the export is stored as Bitwarden's type-2 EncString
(`io/BitwardenEncrypted.kt`, tested against Bitwarden's own KDF test vectors).
"Account restricted" Bitwarden exports can only be read by Bitwarden itself.

**Logging.** Nothing is logged unless "Debug logging" is switched on in the
menu, which only exists in debug builds (some messages contain key material).

**Careful:** an unencrypted export contains all your private keys (and, from
Bitwarden, your passwords too). Delete it once it is imported.

## Your own tunnel server

[`server/`](server/) has a tunnel server in plain Python and a script to find
a hostname for it, so sign-ins need not pass through Google's server. Choose
it in the app under menu → *Tunnel server* (with Google as a fallback).

## Project layout

```
app/src/main/java/it/snel/passkeychain/
  webauthn/   CredentialKey, Assertion, Cbor      (verified crypto core)
  io/         Bitwarden                           (import/export)
  store/      KeystoreCrypto, PasskeyStore        (encrypted storage)
  provider/   PasskeyProviderService, GetAssertionActivity  (Credential Manager)
  hybrid/     FidoQr, HybridTransport, NoiseTunnelClient,
              AndroidBleAdvertiser, HybridSignInActivity  (cross-device sign-in)
  camera/     QrScanActivity                      (CameraX + ML Kit)
  update/     UpdateChecker                       (self-update)
  ui/         MainActivity + Compose              (UI)
```

## License

PassKeyChain is free software, licensed under the
[GNU General Public License v3.0](LICENSE).
