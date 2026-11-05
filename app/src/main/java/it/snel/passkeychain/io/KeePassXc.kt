package it.snel.passkeychain.io

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.CredentialKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * Import/export in the KeePassXC passkey export shape:
 *
 *   { "fido2Credentials": [ { credentialId, keyType, keyAlgorithm, keyCurve,
 *       keyValue, rpId, counter, discoverable, creationDate, userHandle,
 *       userName, rpName, userDisplayName } ] }
 *
 * Import is deliberately tolerant: it accepts a top-level object with
 * `fido2Credentials`, a bare array, or a single credential object, and it
 * accepts `keyValue` as PEM, base64(PKCS#8) or raw base64/base64url scalar.
 * Everything is normalised to the app's canonical internal form. Export emits
 * the structure above with keyValue as PEM for broad interoperability.
 */
object KeePassXc {

    class ImportResult(val imported: List<Passkey>, val skipped: List<String>)

    fun parse(text: String): ImportResult {
        val creds = extractArray(text)
        val out = ArrayList<Passkey>()
        val skipped = ArrayList<String>()
        for (i in 0 until creds.length()) {
            val o = creds.getJSONObject(i)
            runCatching { out.add(parseOne(o)) }
                .onFailure { skipped.add((o.optString("userName").ifBlank { o.optString("rpId") }) + ": " + it.message) }
        }
        return ImportResult(out, skipped)
    }

    private fun extractArray(text: String): JSONArray {
        val trimmed = text.trim()
        return when {
            trimmed.startsWith("[") -> JSONArray(trimmed)
            else -> {
                val o = JSONObject(trimmed)
                when {
                    o.has("fido2Credentials") -> o.getJSONArray("fido2Credentials")
                    o.has("credentialId") || o.has("keyValue") -> JSONArray().put(o)
                    else -> throw IllegalArgumentException("no fido2Credentials found")
                }
            }
        }
    }

    private fun parseOne(o: JSONObject): Passkey {
        val rawKey = o.optString("keyValue").ifBlank { throw IllegalArgumentException("missing keyValue") }
        require(rawKey != "secret") { "keyValue is redacted ('secret') — export a real key" }
        val pkcs8 = CredentialKey.toCanonicalPkcs8(rawKey) // validates the key too
        return Passkey(
            credentialId = toB64Url(o.getString("credentialId")),
            keyType = o.optString("keyType", "public-key"),
            keyAlgorithm = o.optString("keyAlgorithm", "ECDSA"),
            keyCurve = o.optString("keyCurve", "P-256"),
            keyValuePkcs8 = pkcs8,
            rpId = o.getString("rpId"),
            rpName = o.optString("rpName", ""),
            userHandle = toB64Url(o.optString("userHandle", "")),
            userName = o.optString("userName", ""),
            userDisplayName = o.optString("userDisplayName", ""),
            counter = o.optString("counter", "0").toLongOrNull() ?: 0,
            discoverable = o.optString("discoverable", "true").toBoolean(),
            creationDate = o.optString("creationDate", ""),
        )
    }

    fun export(list: List<Passkey>): String {
        val arr = JSONArray()
        for (pk in list) {
            arr.put(JSONObject().apply {
                put("credentialId", toStandardB64(pk.credentialId))
                put("keyType", pk.keyType)
                put("keyAlgorithm", pk.keyAlgorithm)
                put("keyCurve", pk.keyCurve)
                put("keyValue", pkcs8ToPem(pk.keyValuePkcs8))
                put("rpId", pk.rpId)
                put("counter", pk.counter.toString())
                put("discoverable", pk.discoverable.toString())
                put("creationDate", pk.creationDate)
                put("userHandle", toStandardB64(pk.userHandle))
                put("userName", pk.userName)
                put("rpName", pk.rpName)
                put("userDisplayName", pk.userDisplayName)
            })
        }
        return JSONObject().put("fido2Credentials", arr).toString(2)
    }

    // ---- encoding helpers ---------------------------------------------------
    private fun toB64Url(s: String): String = if (s.isBlank()) "" else B64.url(B64.any(s))

    private fun toStandardB64(s: String): String = if (s.isBlank()) "" else B64.std(B64.any(s))

    private fun pkcs8ToPem(b64pkcs8: String): String {
        val b = b64pkcs8.replace(Regex("\\s"), "")
        val sb = StringBuilder("-----BEGIN PRIVATE KEY-----\n")
        var i = 0
        while (i < b.length) { sb.append(b, i, minOf(i + 64, b.length)).append('\n'); i += 64 }
        return sb.append("-----END PRIVATE KEY-----\n").toString()
    }
}
