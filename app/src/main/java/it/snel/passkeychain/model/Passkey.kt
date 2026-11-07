package it.snel.passkeychain.model

import org.json.JSONObject

/**
 * A single stored passkey (FIDO2 discoverable credential) together with the
 * imported private key material. Mirrors the fields of the Bitwarden passkey
 * export format so import/export is lossless.
 *
 * [keyValuePkcs8] always holds the private key as base64 (standard) of its
 * PKCS#8 DER encoding — we normalise whatever encoding was imported into this
 * single canonical form so the rest of the app has one thing to deal with.
 */
data class Passkey(
    val credentialId: String,          // base64url, no padding (WebAuthn id)
    val keyType: String = "public-key",
    val keyAlgorithm: String = "ECDSA",
    val keyCurve: String = "P-256",
    val keyValuePkcs8: String,         // base64(PKCS#8 DER) of the EC private key
    val rpId: String,
    val rpName: String = "",
    val userHandle: String,            // base64url, no padding
    val userName: String = "",
    val userDisplayName: String = "",
    val counter: Long = 0,
    val discoverable: Boolean = true,
    val creationDate: String = "",
) {
    val label: String get() = userName.ifBlank { userDisplayName.ifBlank { rpId } }

    fun toJson(): JSONObject = JSONObject().apply {
        put("credentialId", credentialId)
        put("keyType", keyType)
        put("keyAlgorithm", keyAlgorithm)
        put("keyCurve", keyCurve)
        put("keyValue", keyValuePkcs8)
        put("rpId", rpId)
        put("rpName", rpName)
        put("userHandle", userHandle)
        put("userName", userName)
        put("userDisplayName", userDisplayName)
        put("counter", counter.toString())
        put("discoverable", discoverable.toString())
        put("creationDate", creationDate)
    }
}
