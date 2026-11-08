package it.snel.passkeychain.io

import it.snel.passkeychain.io.BitwardenEncrypted.EncString
import it.snel.passkeychain.io.BitwardenEncrypted.Keys
import it.snel.passkeychain.model.Passkey
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLEncoder
import java.security.KeyFactory
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Read-only sync of passkeys from a Bitwarden-compatible server (Vaultwarden,
 * or Bitwarden itself), the way Bitwarden's own clients log in:
 *
 *  1. prelogin: the server says how the master password is stretched (KDF);
 *  2. master key = KDF(password, email); login hash = PBKDF2(master key, password, 1);
 *  3. token: the login hash buys an access token (and a refresh token, so the
 *     next sync needs no second factor), or the saved refresh token does;
 *  4. sync: the vault, with every field encrypted;
 *  5. decryption, of passkeys only: the user key (from the master key), the
 *     organisation keys (RSA, with the user's private key) and per-item keys
 *     open the fido2Credentials fields. Passwords, notes and the rest are not
 *     decrypted.
 *
 * The result is a Bitwarden export document with just the passkeys, for the
 * normal import. [upload] goes the other way, carefully: it only adds new
 * login items for passkeys the vault doesn't have, and never changes or
 * deletes an existing item.
 */
class VaultSync(serverUrl: String, http: Http, private val deviceId: String) {

    /** The few HTTP calls needed; [OkHttpVault] in the app, a fake in tests. */
    interface Http {
        class Response(val code: Int, val body: String)
        fun post(url: String, contentType: String, body: String, headers: Map<String, String>): Response
        fun get(url: String, headers: Map<String, String>): Response
    }

    class Failure(message: String, cause: Throwable? = null) : Exception(message, cause)
    class WrongPassword : Exception("Wrong master password.")

    /** The server wants a second factor: one of [providers] (see [providerName]). */
    class TwoFactorRequired(val providers: List<Int>) : Exception("A second factor is needed.")

    class TwoFactor(val provider: Int, val code: String)

    class Result(
        /** A Bitwarden export with only the passkeys, for [Bitwarden.parse]. */
        val exportJson: String,
        val passkeyCount: Int,
        /** Passkeys that could not be decrypted, with the reason. */
        val skipped: List<String>,
        /** To save for the next sync; null if the server gave none. */
        val refreshToken: String?,
    )

    private val http = object : Http {
        // Vaultwarden logs an error for calls without a client version
        private fun withClient(h: Map<String, String>) = h + mapOf("Bitwarden-Client-Name" to CLIENT_ID, "Bitwarden-Client-Version" to CLIENT_VERSION)
        override fun post(url: String, contentType: String, body: String, headers: Map<String, String>) = http.post(url, contentType, body, withClient(headers))
        override fun get(url: String, headers: Map<String, String>) = http.get(url, withClient(headers))
    }

    val base: String = normalize(serverUrl)
    private val identity = "$base/identity"
    private val api = "$base/api"

    /**
     * Signed in, with the vault fetched and its key unlocked. The keys live only
     * in memory, as long as this object.
     */
    class Session internal constructor(
        internal val vault: JSONObject,
        internal val userKey: Keys,
        internal val accessToken: String,
        /** To save for the next sync; null if the server gave none. */
        val refreshToken: String?,
        /** The account id (profile id, else the token's "sub"): new items say they are encrypted for it. */
        internal val userId: String?,
    )

    /** Signs in and fetches the vault; [WrongPassword] if the password doesn't open it. */
    fun open(email: String, password: String, savedRefreshToken: String?, twoFactor: TwoFactor? = null): Session {
        val account = email.trim().lowercase()
        val kdf = prelogin(account)
        val master = BitwardenEncrypted.masterKey(password, account, kdf)
        val tokens = savedRefreshToken?.let { runCatching { refresh(it) }.getOrNull() }
            ?: login(account, loginHash(master, password), twoFactor)
        val vault = fetchVault(tokens.access)
        val profile = vault.ci("profile") as? JSONObject ?: throw Failure("The vault has no profile.")
        val userKey = try {
            keysOf(EncString.decrypt(profile.ci("key").toString(), BitwardenEncrypted.stretch(master)))
        } catch (e: IllegalArgumentException) {
            throw WrongPassword()
        }
        val userId = profile.ci("id")?.takeIf { it != JSONObject.NULL }?.toString() ?: tokenSubject(tokens.access)
        return Session(vault, userKey, tokens.access, tokens.refresh ?: savedRefreshToken, userId)
    }

    /** Signs in, fetches the vault and decrypts its passkeys. */
    fun sync(email: String, password: String, savedRefreshToken: String?, twoFactor: TwoFactor? = null): Result =
        open(email, password, savedRefreshToken, twoFactor).let { session ->
            val (export, count, skipped) = decryptPasskeys(session.vault, session.userKey)
            Result(export, count, skipped, session.refreshToken)
        }

    /** The passkeys in the vault of [session], as a Bitwarden export. */
    fun passkeys(session: Session): Result {
        val (export, count, skipped) = decryptPasskeys(session.vault, session.userKey)
        return Result(export, count, skipped, session.refreshToken)
    }

    class Upload(val added: List<Passkey>, val failed: List<String>)

    /**
     * Adds [passkeys] to the vault as new login items (one per site and account,
     * like Bitwarden's export), encrypted with the account's key. Only adds: the
     * caller passes passkeys the vault doesn't have yet.
     */
    fun upload(session: Session, passkeys: List<Passkey>): Upload {
        val added = mutableListOf<Passkey>()
        val failed = mutableListOf<String>()
        for (group in passkeys.groupBy { it.rpId to it.userName }.values) {
            val item = JSONObject(Bitwarden.export(group)).getJSONArray("items").getJSONObject(0)
            val r = http.post(
                "$api/ciphers", JSON, newCipher(item, session.userKey, session.userId).toString(),
                mapOf("Authorization" to "Bearer ${session.accessToken}"),
            )
            if (r.code in 200..299) added += group else failed += "${item.optString("name")}: ${errorMessage(r)}"
        }
        return Upload(added, failed)
    }

    /** Asks the server to email a login code (second factor "Email"). */
    fun sendEmailCode(email: String, password: String) {
        val account = email.trim().lowercase()
        val master = BitwardenEncrypted.masterKey(password, account, prelogin(account))
        val body = JSONObject().put("email", account).put("masterPasswordHash", loginHash(master, password)).toString()
        val r = http.post("$api/two-factor/send-email-login", JSON, body, emptyMap())
        if (r.code !in 200..299) throw Failure("The server could not send a code: ${errorMessage(r)}")
    }

    // ---- server calls --------------------------------------------------------------------

    fun prelogin(email: String): BitwardenEncrypted.Kdf {
        val body = JSONObject().put("email", email).toString()
        var r = http.post("$identity/accounts/prelogin", JSON, body, emptyMap())
        if (r.code == 404) r = http.post("$api/accounts/prelogin", JSON, body, emptyMap()) // older servers
        if (r.code !in 200..299) throw Failure("The server did not answer as a Bitwarden server would (${errorMessage(r)}). Check the address.")
        val o = parse(r)
        val kdf = JSONObject()
            .put("kdfType", o.ci("kdf") ?: 0)
            .put("kdfIterations", o.ci("kdfIterations"))
            .put("kdfMemory", o.ci("kdfMemory") ?: JSONObject.NULL)
            .put("kdfParallelism", o.ci("kdfParallelism") ?: JSONObject.NULL)
        return try {
            BitwardenEncrypted.kdfFrom(kdf)
        } catch (e: BitwardenEncrypted.Unsupported) {
            throw Failure("This account's key settings are not supported: ${e.message}")
        }
    }

    private class Tokens(val access: String, val refresh: String?)

    private fun login(email: String, hash: String, twoFactor: TwoFactor?): Tokens {
        val form = linkedMapOf(
            "grant_type" to "password",
            "username" to email,
            "password" to hash,
            "scope" to "api offline_access",
            "client_id" to CLIENT_ID,
            "deviceType" to DEVICE_TYPE,
            "deviceIdentifier" to deviceId,
            "deviceName" to DEVICE_NAME,
        )
        if (twoFactor != null) {
            form["twoFactorProvider"] = twoFactor.provider.toString()
            form["twoFactorToken"] = twoFactor.code.trim()
            form["twoFactorRemember"] = "0"
        }
        val headers = mapOf(
            "Auth-Email" to Base64.getUrlEncoder().withoutPadding().encodeToString(email.toByteArray()),
            "Device-Type" to DEVICE_TYPE,
        )
        val r = http.post("$identity/connect/token", FORM, formBody(form), headers)
        if (r.code in 200..299) return tokens(parse(r))
        val o = runCatching { parse(r) }.getOrNull()
        val providers = o?.let(::twoFactorProviders).orEmpty()
        if (providers.isNotEmpty()) throw TwoFactorRequired(providers)
        throw Failure(errorMessage(r))
    }

    private fun refresh(refreshToken: String): Tokens {
        val form = mapOf("grant_type" to "refresh_token", "client_id" to CLIENT_ID, "refresh_token" to refreshToken)
        val r = http.post("$identity/connect/token", FORM, formBody(form), emptyMap())
        if (r.code !in 200..299) throw Failure(errorMessage(r))
        return tokens(parse(r))
    }

    private fun tokens(o: JSONObject) = Tokens(
        access = o.ci("access_token")?.toString() ?: throw Failure("The server gave no access token."),
        refresh = o.ci("refresh_token")?.toString(),
    )

    private fun fetchVault(accessToken: String): JSONObject {
        val r = http.get("$api/sync?excludeDomains=true", mapOf("Authorization" to "Bearer $accessToken"))
        if (r.code !in 200..299) throw Failure("Could not fetch the vault: ${errorMessage(r)}")
        return parse(r)
    }

    companion object {
        const val CLIENT_ID = "mobile"
        /** The Bitwarden app version whose API this client speaks. */
        const val CLIENT_VERSION = "2025.10.0"
        const val DEVICE_TYPE = "0" // Android
        const val DEVICE_NAME = "PassKeyChain"
        private const val JSON = "application/json"
        private const val FORM = "application/x-www-form-urlencoded; charset=utf-8"

        const val PROVIDER_AUTHENTICATOR = 0
        const val PROVIDER_EMAIL = 1

        fun providerName(p: Int) = when (p) {
            0 -> "authenticator app"; 1 -> "email"; 2 -> "Duo"; 3 -> "YubiKey OTP"
            6 -> "Duo (organisation)"; 7 -> "security key"; else -> "method $p"
        }

        /** "vault.example.com" -> "https://vault.example.com"; only https. */
        fun normalize(url: String): String {
            var u = url.trim().trimEnd('/')
            if (!u.contains("://")) u = "https://$u"
            val uri = try { URI(u) } catch (e: Exception) { throw Failure("That is not a server address.") }
            if (uri.scheme != "https" || uri.host.isNullOrEmpty()) throw Failure("Use the https address of your server.")
            return u
        }

        /** The hash the server checks: PBKDF2-SHA256(master key, salt = password, 1 iteration), base64. */
        fun loginHash(master: ByteArray, password: String): String =
            Base64.getEncoder().encodeToString(
                BitwardenEncrypted.pbkdf2Sha256(master, password.toByteArray(Charsets.UTF_8), 1, 32),
            )

        private fun formBody(form: Map<String, String>) =
            form.entries.joinToString("&") { (k, v) -> enc(k) + "=" + enc(v) }

        private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

        private fun parse(r: Http.Response): JSONObject = try {
            JSONObject(r.body)
        } catch (e: Exception) {
            throw Failure("The server's answer was not understood (HTTP ${r.code}).")
        }

        private fun twoFactorProviders(o: JSONObject): List<Int> {
            (o.ci("TwoFactorProviders2") as? JSONObject)?.let { m -> return m.keys().asSequence().mapNotNull { it.toIntOrNull() }.toList() }
            (o.ci("TwoFactorProviders") as? JSONArray)?.let { a -> return (0 until a.length()).mapNotNull { a.opt(it)?.toString()?.toIntOrNull() } }
            return emptyList()
        }

        /** The most human message in an error answer. */
        fun errorMessage(r: Http.Response): String {
            val o = runCatching { JSONObject(r.body) }.getOrNull() ?: return "HTTP ${r.code}"
            (o.ci("ErrorModel") as? JSONObject)?.ci("Message")?.toString()?.takeIf { it.isNotBlank() }?.let { return it }
            o.ci("message")?.toString()?.takeIf { it.isNotBlank() }?.let { return it }
            o.ci("error_description")?.toString()?.takeIf { it.isNotBlank() }?.let { return it }
            return "HTTP ${r.code}"
        }

        // ---- decryption -----------------------------------------------------------------

        private val CREDENTIAL_FIELDS = listOf(
            "credentialId", "keyType", "keyAlgorithm", "keyCurve", "keyValue", "rpId", "userHandle",
            "userName", "counter", "rpName", "userDisplayName", "discoverable",
        )

        private data class Decrypted(val exportJson: String, val count: Int, val skipped: List<String>)

        /** The passkeys in a /api/sync answer, decrypted with the account's user key. */
        private fun decryptPasskeys(vault: JSONObject, userKey: Keys): Decrypted {
            val profile = vault.ci("profile") as? JSONObject ?: throw Failure("The vault has no profile.")
            // organisation keys: RSA-encrypted with the user's private key
            val orgKeys = HashMap<String, Keys>()
            val orgs = profile.ci("organizations") as? JSONArray
            val skipped = mutableListOf<String>()
            if (orgs != null && orgs.length() > 0) {
                val privateKey = profile.ci("privateKey")?.toString()?.let { EncString.decrypt(it, userKey) }
                for (i in 0 until orgs.length()) {
                    val org = orgs.getJSONObject(i)
                    val id = org.ci("id")?.toString() ?: continue
                    val key = org.ci("key")?.toString() ?: continue
                    runCatching { keysOf(rsaDecrypt(key, privateKey ?: throw Failure("no private key"))) }
                        .onSuccess { orgKeys[id] = it }
                }
            }
            val credentials = JSONArray()
            val ciphers = vault.ci("ciphers") as? JSONArray ?: JSONArray()
            for (i in 0 until ciphers.length()) {
                val c = ciphers.optJSONObject(i) ?: continue
                if (c.ci("deletedDate").let { it != null && it != JSONObject.NULL }) continue // in the trash
                val login = c.ci("login") as? JSONObject ?: continue
                val fido = login.ci("fido2Credentials") as? JSONArray ?: continue
                if (fido.length() == 0) continue
                try {
                    val orgId = c.ci("organizationId")?.takeIf { it != JSONObject.NULL }?.toString()
                    var keys = if (orgId != null) orgKeys[orgId] ?: throw Failure("no key for its organisation") else userKey
                    c.ci("key")?.takeIf { it != JSONObject.NULL }?.let { keys = keysOf(EncString.decrypt(it.toString(), keys)) }
                    for (j in 0 until fido.length()) {
                        val f = fido.getJSONObject(j)
                        val out = JSONObject()
                        for (field in CREDENTIAL_FIELDS) {
                            val v = f.ci(field)
                            if (v != null && v != JSONObject.NULL) out.put(field, String(EncString.decrypt(v.toString(), keys), Charsets.UTF_8))
                        }
                        f.ci("creationDate")?.takeIf { it != JSONObject.NULL }?.let { out.put("creationDate", it.toString()) }
                        credentials.put(out)
                    }
                } catch (e: Exception) {
                    skipped += "an item with ${fido.length()} passkey(s): ${e.message ?: e.javaClass.simpleName}"
                }
            }
            val export = JSONObject().put("encrypted", false).put(
                "items",
                JSONArray().put(JSONObject().put("type", 1).put("login", JSONObject().put("fido2Credentials", credentials))),
            )
            return Decrypted(export.toString(), credentials.length(), skipped)
        }

        /** A Bitwarden export item turned into a new-cipher request: every text field encrypted. */
        private fun newCipher(item: JSONObject, key: Keys, userId: String?): JSONObject {
            fun e(v: Any?): Any = if (v == null || v == JSONObject.NULL || v.toString().isEmpty()) JSONObject.NULL
                else EncString.encrypt(v.toString().toByteArray(Charsets.UTF_8), key)
            val login = item.getJSONObject("login")
            val credentials = JSONArray()
            val src = login.getJSONArray("fido2Credentials")
            for (j in 0 until src.length()) {
                val f = src.getJSONObject(j)
                val out = JSONObject()
                for (field in CREDENTIAL_FIELDS) out.put(field, e(f.opt(field)))
                out.put("creationDate", f.optString("creationDate").ifBlank { java.time.Instant.now().toString() })
                credentials.put(out)
            }
            val uris = JSONArray()
            login.optJSONArray("uris")?.let { a ->
                for (j in 0 until a.length()) uris.put(JSONObject().put("uri", e(a.getJSONObject(j).opt("uri"))).put("match", JSONObject.NULL))
            }
            return JSONObject()
                // required by Vaultwarden 1.37+ (checked against the signed-in account), accepted by Bitwarden
                .put("encryptedFor", userId ?: JSONObject.NULL)
                .put("type", 1)
                .put("organizationId", JSONObject.NULL)
                .put("folderId", JSONObject.NULL)
                .put("favorite", false)
                .put("reprompt", 0)
                .put("name", e(item.optString("name").ifBlank { "Passkey" }))
                .put("notes", JSONObject.NULL)
                .put("login", JSONObject()
                    .put("username", e(login.opt("username")))
                    .put("password", JSONObject.NULL)
                    .put("totp", JSONObject.NULL)
                    .put("uris", uris)
                    .put("fido2Credentials", credentials))
        }

        /** The "sub" claim of a JWT access token, or null. */
        private fun tokenSubject(jwt: String): String? = runCatching {
            JSONObject(String(Base64.getUrlDecoder().decode(jwt.split(".")[1].trimEnd('=')), Charsets.UTF_8)).optString("sub").ifBlank { null }
        }.getOrNull()

        private fun keysOf(b: ByteArray): Keys {
            if (b.size != 64) throw Failure("unexpected key length ${b.size}")
            return Keys(b.copyOfRange(0, 32), b.copyOfRange(32, 64))
        }

        /** EncString types 3 and 4 (and 5/6 with a MAC, which is ignored): RSA-2048-OAEP, SHA-256 or SHA-1. */
        private fun rsaDecrypt(s: String, pkcs8: ByteArray): ByteArray {
            val type = s.substringBefore('.').toIntOrNull() ?: throw Failure("malformed key")
            val data = Base64.getDecoder().decode(s.substringAfter('.').substringBefore('|'))
            val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            val spec = when (type) {
                3, 5 -> OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
                4, 6 -> OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
                else -> throw Failure("unsupported key type $type")
            }
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            return cipher.doFinal(data)
        }

        /** A member by name, ignoring case: servers differ (Vaultwarden once used PascalCase). */
        private fun JSONObject.ci(name: String): Any? {
            if (has(name)) return opt(name)
            for (k in keys()) if (k.equals(name, ignoreCase = true)) return opt(k)
            return null
        }
    }
}
