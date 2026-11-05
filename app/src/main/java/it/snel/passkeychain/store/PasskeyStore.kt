package it.snel.passkeychain.store

import android.content.Context
import it.snel.passkeychain.model.Passkey
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Persists the imported passkeys as a single AES-GCM encrypted file in the
 * app's private storage. The in-memory list is the source of truth during a
 * session; every mutation re-encrypts and rewrites the file atomically.
 */
class PasskeyStore(context: Context) {

    private val file = File(context.filesDir, "passkeys.enc")
    private val lock = Any()

    fun load(): List<Passkey> = synchronized(lock) {
        if (!file.exists()) return emptyList()
        return runCatching {
            val json = KeystoreCrypto.decrypt(file.readBytes()).toString(Charsets.UTF_8)
            val arr = JSONArray(json)
            (0 until arr.length()).map { parse(arr.getJSONObject(it)) }
        }.getOrElse { emptyList() }
    }

    fun save(list: List<Passkey>) = synchronized(lock) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        val blob = KeystoreCrypto.encrypt(arr.toString().toByteArray(Charsets.UTF_8))
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(blob)
        if (!tmp.renameTo(file)) { file.writeBytes(blob); tmp.delete() }
    }

    fun upsert(pk: Passkey): List<Passkey> {
        val list = load().toMutableList()
        val i = list.indexOfFirst { it.credentialId == pk.credentialId && it.rpId == pk.rpId }
        if (i >= 0) list[i] = pk else list.add(pk)
        save(list)
        return list
    }

    fun delete(credentialId: String, rpId: String): List<Passkey> {
        val list = load().filterNot { it.credentialId == credentialId && it.rpId == rpId }
        save(list)
        return list
    }

    /** Candidates for a get request: by rpId, optionally restricted to an allow-list of ids. */
    fun candidatesFor(rpId: String, allowCredentialIds: Set<String>? = null): List<Passkey> =
        load().filter { it.rpId == rpId && (allowCredentialIds == null || it.credentialId in allowCredentialIds) }

    private fun parse(o: JSONObject): Passkey = Passkey(
        credentialId = o.getString("credentialId"),
        keyType = o.optString("keyType", "public-key"),
        keyAlgorithm = o.optString("keyAlgorithm", "ECDSA"),
        keyCurve = o.optString("keyCurve", "P-256"),
        keyValuePkcs8 = o.getString("keyValue"),
        rpId = o.getString("rpId"),
        rpName = o.optString("rpName", ""),
        userHandle = o.optString("userHandle", ""),
        userName = o.optString("userName", ""),
        userDisplayName = o.optString("userDisplayName", ""),
        counter = o.optString("counter", "0").toLongOrNull() ?: 0,
        discoverable = o.optString("discoverable", "true").toBoolean(),
        creationDate = o.optString("creationDate", ""),
    )
}
