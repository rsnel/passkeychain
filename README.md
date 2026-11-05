# PassKeyChain

An open-source Android app that **imports your FIDO2 passkeys**, stores the
private keys in Android Keystore-encrypted storage, uses them to sign in — both
on-device (as a system passkey provider) and across devices (by scanning a
sign-in QR) — and can **export** them again. It keeps itself up to date from
GitHub Releases.

> PassKeyChain manages credentials **you already own**. Keys never leave your
> device; there is no server and no telemetry. Passkey import/export follows the
> FIDO Alliance Credential Exchange direction (2025).

Website / screenshots: **https://rsnel.github.io/passkeychain/**

---

## Status (honest)

**Working and unit-tested** (re-verified in CI on every build):

- KeePassXC import/export round-trip
- P-256 private-key decoding across PEM / base64-PKCS#8 / raw-scalar encodings
- WebAuthn **ES256 assertion signing** (`authenticatorData || clientDataHash`)
- FIDO `FIDO:/` hybrid **QR decoding** (base-10 digit packing + CBOR)
- Keystore-encrypted storage, Jetpack Compose UI, self-update channel logic

**In progress — needs a physical device to finish:**

- The hybrid/caBLE **BLE proximity advertisement**
- The **Noise-encrypted relay tunnel** (CTAP2 over the tunnel)
- End-to-end sign-in against a live Microsoft login

The deterministic cryptography for the hybrid flow *is* implemented and tested;
the radio/network stages (`hybrid/HybridTransport.kt`) throw
`DeviceStageMissing` rather than pretend to work.

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

Release builds are prepared but not used yet: pushing a `v*` tag would build
`assembleRelease`, signed via the repository secrets `KEYSTORE_BASE64`,
`KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD` (locally: copy
`keystore.properties.example` to `keystore.properties`), and publish it as a
GitHub release that the release app follows via `/releases/latest`.

## Import format

KeePassXC passkey export:

```json
{ "fido2Credentials": [ {
    "credentialId": "...", "keyType": "public-key", "keyAlgorithm": "ECDSA",
    "keyCurve": "P-256", "keyValue": "-----BEGIN PRIVATE KEY----- ...",
    "rpId": "login.microsoft.com", "userHandle": "...", "userName": "...",
    "rpName": "Microsoft", "userDisplayName": "...", "counter": "0",
    "discoverable": "true" } ] }
```

A throwaway example (dummy key) is at [`docs/sample-passkey.json`](docs/sample-passkey.json).
The importer also accepts a bare array or a single credential object, and
`keyValue` as PEM, base64 PKCS#8, or raw base64/base64url scalar.

## Project layout

```
app/src/main/java/it/snel/passkeychain/
  webauthn/   CredentialKey, Assertion, Cbor      (verified crypto core)
  io/         KeePassXc                           (import/export)
  store/      KeystoreCrypto, PasskeyStore        (encrypted storage)
  provider/   PasskeyProviderService, GetAssertionActivity  (Credential Manager)
  hybrid/     FidoQr, HybridTransport             (cross-device caBLE)
  camera/     QrScanActivity                      (CameraX + ML Kit)
  update/     UpdateChecker                       (self-update)
  ui/         MainActivity + Compose              (UI)
```

## License

PassKeyChain is free software, licensed under the
[GNU General Public License v3.0](LICENSE).
