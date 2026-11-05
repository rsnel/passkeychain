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

## Signing

- **Debug** uses the committed, deterministic `app/debug.keystore` (standard
  `android`/`androiddebugkey` creds). It is intentionally in the repo so every
  debug build — local or CI — shares one signature, which is required for the
  in-app updater to replace a previous debug install.
- **Release** reads credentials from `keystore.properties` (copy
  `keystore.properties.example`) or the environment / CI secrets
  `RELEASE_STORE_FILE`, `RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS`,
  `RELEASE_KEY_PASSWORD`. Release is configured but **not built yet**.

## Releases & self-update

The app only looks at **its own channel**:

| Build   | Tag pattern        | Release type |
|---------|--------------------|--------------|
| debug   | `debug-v<name>+<code>` | pre-release |
| release | `v<name>+<code>`       | release     |

The trailing `+<code>` is the Android `versionCode`; the updater installs a
release whose code is higher than the running one. Cut a debug build for the
updater like:

```bash
git tag debug-v0.1.0+1 && git push origin debug-v0.1.0+1
```

CI builds the APK and publishes it to that release automatically.

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

Not yet chosen — add one (e.g. MIT or GPL-3.0) before publishing widely.
