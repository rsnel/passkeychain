package it.snel.passkeychain.io

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.CredentialKey
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

/**
 * Reads passkeys from the FIDO Credential Exchange Format (CXF 1.0), the JSON
 * that Android's credential transfer (and other password managers) produce:
 * a header with accounts, each with items, each with credentials. A passkey
 * credential is {"type": "passkey", "credentialId", "rpId", "username",
 * "userDisplayName", "userHandle", "key"}, where credentialId and userHandle
 * are base64url and key is the PKCS#8 private key, base64url.
 *
 * Passkeys are found wherever they are in the document, like the Bitwarden
 * importer does; other credential types (passwords, cards, notes) are ignored.
 */
object Cxf {

    /** Whether [text] is JSON with at least one CXF passkey in it. */
    fun hasPasskeys(text: String): Boolean = runCatching { find(text).isNotEmpty() }.getOrDefault(false)

    fun parse(text: String): Bitwarden.ImportResult {
        val found = find(text)
        if (found.isEmpty()) throw IllegalArgumentException("no passkeys found in this Credential Exchange document")
        val out = ArrayList<Passkey>()
        val skipped = ArrayList<String>()
        for ((cred, item) in found) {
            runCatching { out.add(parseOne(cred, item)) }
                .onFailure { skipped.add(cred.optString("username").ifBlank { cred.optString("rpId") } + ": " + it.message) }
        }
        return Bitwarden.ImportResult(out, skipped)
    }

    /** (passkey credential, the item it belongs to or null) for every passkey in the document */
    private fun find(text: String): List<Pair<JSONObject, JSONObject?>> {
        val t = text.trim()
        val root: Any = if (t.startsWith("[")) JSONArray(t) else JSONObject(t)
        val out = ArrayList<Pair<JSONObject, JSONObject?>>()
        collect(root, null, out)
        return out
    }

    private fun collect(node: Any?, item: JSONObject?, out: MutableList<Pair<JSONObject, JSONObject?>>) {
        when (node) {
            is JSONObject -> {
                if (node.optString("type") == "passkey" && node.has("key") && node.has("rpId")) { out.add(node to item); return }
                // an item: something with credentials; remember it for the title and dates
                val here = if (node.has("credentials")) node else item
                for (key in node.keys()) collect(node.opt(key), here, out)
            }
            is JSONArray -> for (i in 0 until node.length()) collect(node.opt(i), item, out)
        }
    }

    private fun parseOne(c: JSONObject, item: JSONObject?): Passkey {
        val key = c.optString("key").ifBlank { throw IllegalArgumentException("missing key") }
        val pkcs8 = CredentialKey.toCanonicalPkcs8(B64.std(B64.any(key))) // validates the key too
        val created = item?.optLong("creationAt", 0L)?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it).toString() } ?: ""
        return Passkey(
            credentialId = B64.url(B64.any(c.getString("credentialId"))),
            keyValuePkcs8 = pkcs8,
            rpId = c.getString("rpId"),
            rpName = item?.optString("title").orEmpty(),
            userHandle = c.optString("userHandle").let { if (it.isBlank()) "" else B64.url(B64.any(it)) },
            userName = c.optString("username"),
            userDisplayName = c.optString("userDisplayName"),
            creationDate = created,
            // it came from another manager, which keeps its copy: backed up
            backedUp = true,
        )
    }
}
