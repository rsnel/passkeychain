package it.snel.passkeychain.store

import android.content.Context
import java.util.Base64
import java.util.UUID

/**
 * The server and account of the last vault sync, a device id for this phone,
 * and the server's refresh token (Keystore-encrypted), so the next sync needs
 * the master password but no second factor. The master password and the
 * vault's keys are never stored.
 */
class VaultSettings(context: Context) {
    private val prefs = context.getSharedPreferences("vault_sync", Context.MODE_PRIVATE)

    var server: String
        get() = prefs.getString("server", "") ?: ""
        set(v) { prefs.edit().putString("server", v).apply() }

    var email: String
        get() = prefs.getString("email", "") ?: ""
        set(v) { prefs.edit().putString("email", v).apply() }

    val deviceId: String
        get() = prefs.getString("device_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_id", it).apply()
        }

    /** The refresh token, if it belongs to [server] and [email]. */
    fun refreshToken(server: String, email: String): String? {
        if (server != this.server || !email.equals(this.email, ignoreCase = true)) return null
        val blob = prefs.getString("refresh_token", null) ?: return null
        return runCatching { String(KeystoreCrypto.decrypt(Base64.getDecoder().decode(blob)), Charsets.UTF_8) }.getOrNull()
    }

    fun save(server: String, email: String, refreshToken: String?) {
        val e = prefs.edit().putString("server", server).putString("email", email.trim())
        if (refreshToken != null) e.putString("refresh_token", Base64.getEncoder().encodeToString(KeystoreCrypto.encrypt(refreshToken.toByteArray())))
        else e.remove("refresh_token")
        e.apply()
    }

    fun hasToken() = prefs.contains("refresh_token")

    /** Forgets the server, the account and the token. */
    fun forget() = prefs.edit().remove("server").remove("email").remove("refresh_token").apply()
}
