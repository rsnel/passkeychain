package it.snel.passkeychain.webauthn

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Builds a WebAuthn assertion (the `navigator.credentials.get` response) for a
 * stored [Passkey]. Used by both the on-device Credential Manager provider and
 * the cross-device hybrid flow.
 */
object Assertion {

    const val FLAG_UP = 0x01   // user present
    const val FLAG_UV = 0x04   // user verified
    const val FLAG_BE = 0x08   // backup eligible
    const val FLAG_BS = 0x10   // backup state (currently backed up)

    data class Result(
        val clientDataJson: ByteArray?,   // null when the caller supplied a clientDataHash
        val authenticatorData: ByteArray,
        val signature: ByteArray,
    )

    /** authenticatorData = sha256(rpId) || flags || signCount(BE) */
    fun authenticatorData(rpId: String, flags: Int, signCount: Long): ByteArray {
        val rpIdHash = sha256(rpId.toByteArray(Charsets.UTF_8))
        val o = ByteArrayOutputStream()
        o.write(rpIdHash)
        o.write(flags and 0xFF)
        o.write(((signCount ushr 24) and 0xFF).toInt())
        o.write(((signCount ushr 16) and 0xFF).toInt())
        o.write(((signCount ushr 8) and 0xFF).toInt())
        o.write((signCount and 0xFF).toInt())
        return o.toByteArray()
    }

    fun clientDataJson(challengeB64Url: String, origin: String, crossOrigin: Boolean = false): ByteArray =
        JSONObject().apply {
            put("type", "webauthn.get")
            put("challenge", challengeB64Url)
            put("origin", origin)
            put("crossOrigin", crossOrigin)
        }.toString().toByteArray(Charsets.UTF_8)

    /**
     * Produce an assertion.
     *
     * If [clientDataHash] is non-null (privileged/browser caller supplied it),
     * we sign over that hash and do not synthesise a clientDataJSON. Otherwise
     * we build a clientDataJSON from [challengeB64Url] + [origin] and hash it.
     */
    fun create(
        passkey: Passkey,
        challengeB64Url: String,
        origin: String,
        clientDataHash: ByteArray? = null,
        flags: Int = FLAG_UP or FLAG_UV or FLAG_BE or FLAG_BS,
    ): Result {
        val priv = CredentialKey.decodePrivate(passkey.keyValuePkcs8)
        val authData = authenticatorData(passkey.rpId, flags, passkey.counter)

        val cdj: ByteArray?
        val cdHash: ByteArray
        if (clientDataHash != null) {
            cdj = null
            cdHash = clientDataHash
        } else {
            cdj = clientDataJson(challengeB64Url, origin)
            cdHash = sha256(cdj)
        }
        val signed = authData + cdHash
        val sig = CredentialKey.signEs256(priv, signed)
        return Result(cdj, authData, sig)
    }

    /** Full AuthenticatorAssertionResponseJSON string for Credential Manager. */
    fun responseJson(passkey: Passkey, r: Result, attachment: String = "platform"): String {
        val resp = JSONObject().apply {
            r.clientDataJson?.let { put("clientDataJSON", b64u(it)) }
            put("authenticatorData", b64u(r.authenticatorData))
            put("signature", b64u(r.signature))
            put("userHandle", passkey.userHandle) // already base64url
        }
        return JSONObject().apply {
            put("id", passkey.credentialId)
            put("rawId", passkey.credentialId)
            put("type", "public-key")
            put("authenticatorAttachment", attachment)
            put("response", resp)
            put("clientExtensionResults", JSONObject())
        }.toString()
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    private fun b64u(b: ByteArray): String = B64.url(b)
}
