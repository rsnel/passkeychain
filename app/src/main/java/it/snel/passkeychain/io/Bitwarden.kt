package it.snel.passkeychain.io

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.CredentialKey
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Import/export of passkeys in Bitwarden's (unencrypted) JSON export format.
 *
 * A Bitwarden export keeps passkeys inside login items:
 *
 *   { "encrypted": false, "items": [ { "type": 1, "name": "...",
 *       "login": { "username": "...", "uris": [...],
 *         "fido2Credentials": [ { credentialId, keyType, keyAlgorithm, keyCurve,
 *           keyValue, rpId, userHandle, userName, counter, rpName,
 *           userDisplayName, discoverable, creationDate } ] } } ] }
 *
 * Field encodings, as Bitwarden writes them:
 *  - credentialId: a GUID string ("1b2c…-…") for 16-byte ids, otherwise
 *    "b64." followed by the id in base64url
 *  - keyValue: the P-256 private key, PKCS#8 DER in base64url
 *  - userHandle: base64url
 *  - counter and discoverable: strings ("0", "true")
 *
 * Import looks for every "fido2Credentials" array anywhere in the file, so a
 * full export, a single item or just the array all work. keyValue is also
 * accepted as PEM or base64 (older PassKeyChain exports). Everything is
 * normalised to the app's internal form (base64url ids, base64 PKCS#8 key).
 * Export writes a file Bitwarden can import again.
 */
object Bitwarden {

    class ImportResult(val imported: List<Passkey>, val skipped: List<String>)

    private val GUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    fun parse(text: String): ImportResult {
        val creds = ArrayList<JSONObject>()
        collect(parseJson(text), creds)
        if (creds.isEmpty()) throw IllegalArgumentException("no passkeys (fido2Credentials) found in this file")
        val out = ArrayList<Passkey>()
        val skipped = ArrayList<String>()
        for (o in creds) {
            runCatching { out.add(parseOne(o)) }
                .onFailure { skipped.add((o.optString("userName").ifBlank { o.optString("rpId") }) + ": " + it.message) }
        }
        return ImportResult(out, skipped)
    }

    private fun parseJson(text: String): Any {
        val t = text.trim()
        return when {
            t.startsWith("[") -> JSONArray(t)
            t.startsWith("\"") -> JSONObject("{$t}") // just "fido2Credentials": [ … ] pasted from an export
            else -> JSONObject(t)
        }
    }

    /** Finds credential objects: in any "fido2Credentials" array, or a bare credential object/array. */
    private fun collect(node: Any?, out: MutableList<JSONObject>) {
        when (node) {
            is JSONObject -> {
                if (node.has("keyValue") && node.has("rpId")) { out.add(node); return }
                for (key in node.keys()) collect(node.opt(key), out)
            }
            is JSONArray -> for (i in 0 until node.length()) collect(node.opt(i), out)
        }
    }

    private fun parseOne(o: JSONObject): Passkey {
        val rawKey = o.optString("keyValue").ifBlank { throw IllegalArgumentException("missing keyValue") }
        require(rawKey != "secret") { "keyValue is redacted ('secret'): export a real key" }
        val pkcs8 = CredentialKey.toCanonicalPkcs8(rawKey) // also validates the key
        return Passkey(
            credentialId = B64.url(credentialIdBytes(o.getString("credentialId"))),
            keyType = o.optString("keyType", "public-key"),
            keyAlgorithm = o.optString("keyAlgorithm", "ECDSA"),
            keyCurve = o.optString("keyCurve", "P-256"),
            keyValuePkcs8 = pkcs8,
            rpId = o.getString("rpId"),
            rpName = o.optString("rpName", ""),
            userHandle = o.optString("userHandle", "").let { if (it.isBlank()) "" else B64.url(B64.any(it)) },
            userName = o.optString("userName", ""),
            userDisplayName = o.optString("userDisplayName", ""),
            counter = o.optString("counter", "0").toLongOrNull() ?: 0,
            discoverable = o.optString("discoverable", "true").toBoolean(),
            creationDate = o.optString("creationDate", ""),
        )
    }

    /** Bitwarden's credentialId: a GUID for 16-byte ids, "b64.<base64url>" otherwise. */
    fun credentialIdBytes(s: String): ByteArray = when {
        GUID.matches(s) -> hexToBytes(s.replace("-", ""))
        s.startsWith("b64.") -> B64.dUrl(s.removePrefix("b64."))
        else -> B64.any(s) // plain base64/base64url, e.g. older PassKeyChain exports
    }

    fun credentialIdString(id: ByteArray): String =
        if (id.size == 16) {
            val h = id.joinToString("") { "%02x".format(it) }
            "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
        } else "b64." + B64.url(id)

    fun export(list: List<Passkey>): String {
        val items = JSONArray()
        for (group in list.groupBy { it.rpId to it.userName }.values) {
            val first = group.first()
            val creds = JSONArray()
            for (pk in group) {
                creds.put(JSONObject().apply {
                    put("credentialId", credentialIdString(B64.dUrl(pk.credentialId)))
                    put("keyType", pk.keyType)
                    put("keyAlgorithm", pk.keyAlgorithm)
                    put("keyCurve", pk.keyCurve)
                    put("keyValue", B64.url(B64.any(pk.keyValuePkcs8)))
                    put("rpId", pk.rpId)
                    put("userHandle", pk.userHandle)
                    put("userName", pk.userName)
                    put("counter", pk.counter.toString())
                    put("rpName", pk.rpName)
                    put("userDisplayName", pk.userDisplayName)
                    put("discoverable", pk.discoverable.toString())
                    put("creationDate", pk.creationDate)
                })
            }
            items.put(JSONObject().apply {
                put("id", UUID.randomUUID().toString())
                put("organizationId", JSONObject.NULL)
                put("folderId", JSONObject.NULL)
                put("type", 1) // login
                put("reprompt", 0)
                put("name", first.rpName.ifBlank { first.rpId })
                put("notes", JSONObject.NULL)
                put("favorite", false)
                put("login", JSONObject().apply {
                    put("fido2Credentials", creds)
                    put("uris", JSONArray().put(JSONObject().put("match", JSONObject.NULL).put("uri", "https://${first.rpId}")))
                    put("username", if (first.userName.isBlank()) JSONObject.NULL else first.userName)
                    put("password", JSONObject.NULL)
                    put("totp", JSONObject.NULL)
                })
                put("collectionIds", JSONObject.NULL)
            })
        }
        return JSONObject()
            .put("encrypted", false)
            .put("folders", JSONArray())
            .put("items", items)
            .toString(2)
    }

    private fun hexToBytes(h: String): ByteArray = ByteArray(h.length / 2) { i -> h.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}
