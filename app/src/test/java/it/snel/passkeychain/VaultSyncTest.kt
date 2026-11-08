package it.snel.passkeychain

import it.snel.passkeychain.io.Bitwarden
import it.snel.passkeychain.io.BitwardenEncrypted
import it.snel.passkeychain.io.BitwardenEncrypted.EncString
import it.snel.passkeychain.io.BitwardenEncrypted.Keys
import it.snel.passkeychain.io.VaultSync
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLDecoder
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/** VaultSync against a fake Bitwarden-compatible server that encrypts like the real one. */
class VaultSyncTest {
    private val email = "Sam@Example.com " // trimmed and lowercased as salt
    private val account = "sam@example.com"
    private val password = "correct horse battery staple"
    private val iterations = 5000

    private fun random(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }
    private fun keys(b: ByteArray) = Keys(b.copyOfRange(0, 32), b.copyOfRange(32, 64))
    private fun enc(s: String, k: Keys) = EncString.encrypt(s.toByteArray(), k)

    private fun newPkcs8(): String {
        val g = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(g.generateKeyPair().private.encoded)
    }

    private fun credential(k: Keys, id: String, rpId: String, user: String) = JSONObject()
        .put("credentialId", enc(id, k)).put("keyType", enc("public-key", k)).put("keyAlgorithm", enc("ECDSA", k))
        .put("keyCurve", enc("P-256", k)).put("keyValue", enc(newPkcs8(), k)).put("rpId", enc(rpId, k))
        .put("userHandle", enc("dXNlcg", k)).put("userName", enc(user, k)).put("counter", enc("0", k))
        .put("rpName", enc(rpId, k)).put("userDisplayName", enc(user, k)).put("discoverable", enc("true", k))
        .put("creationDate", "2026-10-03T08:00:00.000Z")

    /** The fake server. */
    private inner class Server(val requireTwoFactor: Boolean = false) : VaultSync.Http {
        val master = BitwardenEncrypted.masterKey(password, account, BitwardenEncrypted.Kdf.Pbkdf2(iterations))
        val expectedHash = VaultSync.loginHash(master, password)
        val userKeyBytes = random(64)
        val userKey = keys(userKeyBytes)
        val calls = mutableListOf<String>()
        val vault: JSONObject

        init {
            val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val orgKey = keys(random(64))
            val oaep = Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
                init(Cipher.ENCRYPT_MODE, rsa.public, OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT))
            }
            val orgKeyEnc = "4." + Base64.getEncoder().encodeToString(oaep.doFinal(orgKey.enc + orgKey.mac))
            val itemKey = keys(random(64))
            vault = JSONObject()
                .put("profile", JSONObject()
                    .put("id", "user-1")
                    .put("key", EncString.encrypt(userKeyBytes, BitwardenEncrypted.stretch(master)))
                    .put("privateKey", EncString.encrypt(rsa.private.encoded, userKey))
                    .put("organizations", JSONArray().put(JSONObject().put("id", "org-1").put("key", orgKeyEnc))))
                .put("ciphers", JSONArray()
                    // personal, user key
                    .put(JSONObject().put("type", 1).put("organizationId", JSONObject.NULL).put("key", JSONObject.NULL)
                        .put("login", JSONObject().put("password", enc("never decrypted", userKey))
                            .put("fido2Credentials", JSONArray().put(credential(userKey, "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "example.com", "sam")))))
                    // organisation, with its own item key (PascalCase, like older Vaultwarden)
                    .put(JSONObject().put("Type", 1).put("OrganizationId", "org-1").put("Key", EncString.encrypt(itemKey.enc + itemKey.mac, orgKey))
                        .put("Login", JSONObject().put("Fido2Credentials", JSONArray().put(credential(itemKey, "b64.AQIDBAUGBwgJ", "example.org", "team")))))
                    // in the trash: skipped
                    .put(JSONObject().put("type", 1).put("deletedDate", "2026-11-01T00:00:00Z")
                        .put("login", JSONObject().put("fido2Credentials", JSONArray().put(credential(userKey, "11111111-2222-3333-4444-555555555555", "deleted.example", "x")))))
                    // a login without passkeys
                    .put(JSONObject().put("type", 1).put("login", JSONObject().put("username", enc("sam", userKey)))))
        }

        private fun form(body: String) = body.split("&").associate {
            val (k, v) = it.split("=", limit = 2); URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
        }

        override fun post(url: String, contentType: String, body: String, headers: Map<String, String>): VaultSync.Http.Response {
            calls += url.substringAfter("https://vault.example.net")
            return when {
                url.endsWith("/identity/accounts/prelogin") -> {
                    assertEquals(account, JSONObject(body).getString("email"))
                    VaultSync.Http.Response(200, """{"kdf":0,"kdfIterations":$iterations,"kdfMemory":null,"kdfParallelism":null}""")
                }
                url.endsWith("/identity/connect/token") -> {
                    val f = form(body)
                    when (f["grant_type"]) {
                        "refresh_token" ->
                            if (f["refresh_token"] == "refresh-1") VaultSync.Http.Response(200, """{"access_token":"access-2","refresh_token":"refresh-2"}""")
                            else VaultSync.Http.Response(400, """{"error":"invalid_grant"}""")
                        else -> {
                            assertEquals(account, f["username"]); assertEquals("api offline_access", f["scope"])
                            assertEquals("mobile", f["client_id"]); assertEquals("0", f["deviceType"])
                            when {
                                f["password"] != expectedHash -> VaultSync.Http.Response(400,
                                    """{"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":"Username or password is incorrect. Try again."}}""")
                                requireTwoFactor && f["twoFactorToken"] != "123456" -> VaultSync.Http.Response(400,
                                    """{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0","1"],"TwoFactorProviders2":{"0":null,"1":{"Email":"s***@example.com"}}}""")
                                else -> VaultSync.Http.Response(200, """{"access_token":"access-1","refresh_token":"refresh-1","Key":"..."}""")
                            }
                        }
                    }
                }
                url.endsWith("/api/ciphers") -> {
                    assertEquals("Bearer access-1", headers["Authorization"])
                    val cipher = JSONObject(body)
                    assertEquals(1, cipher.getInt("type"))
                    // like Vaultwarden 1.37: required, and must be the signed-in account
                    if (cipher.optString("encryptedFor") != "user-1") return VaultSync.Http.Response(422, """{"message":"missing field `encryptedFor`"}""")
                    vault.getJSONArray("ciphers").put(cipher.put("id", "new-${vault.getJSONArray("ciphers").length()}"))
                    VaultSync.Http.Response(200, cipher.toString())
                }
                url.endsWith("/api/two-factor/send-email-login") -> {
                    assertEquals(expectedHash, JSONObject(body).getString("masterPasswordHash"))
                    VaultSync.Http.Response(200, "")
                }
                else -> VaultSync.Http.Response(404, "")
            }
        }

        override fun get(url: String, headers: Map<String, String>): VaultSync.Http.Response {
            calls += url.substringAfter("https://vault.example.net")
            assertEquals(VaultSync.CLIENT_VERSION, headers["Bitwarden-Client-Version"])
            assertTrue(headers["Authorization"] == "Bearer access-1" || headers["Authorization"] == "Bearer access-2")
            return VaultSync.Http.Response(200, vault.toString())
        }
    }

    @Test fun syncDecryptsPersonalAndOrganisationPasskeys() {
        val server = Server()
        val r = VaultSync("vault.example.net/", server, "device-1").sync(email, password, savedRefreshToken = null)
        assertEquals(2, r.passkeyCount)
        assertTrue(r.skipped.isEmpty())
        assertEquals("refresh-1", r.refreshToken)
        assertTrue("passwords are not decrypted", !r.exportJson.contains("never decrypted"))
        val imported = Bitwarden.parse(r.exportJson).imported
        assertEquals(setOf("example.com", "example.org"), imported.map { it.rpId }.toSet())
        assertEquals(listOf("/identity/accounts/prelogin", "/identity/connect/token", "/api/sync?excludeDomains=true"), server.calls)
    }

    @Test fun savedRefreshTokenSkipsThePasswordLogin() {
        val server = Server(requireTwoFactor = true) // would need a code with the password
        val r = VaultSync("https://vault.example.net", server, "device-1").sync(email, password, savedRefreshToken = "refresh-1")
        assertEquals(2, r.passkeyCount)
        assertEquals("refresh-2", r.refreshToken)
    }

    @Test fun wrongPasswordWithRefreshTokenIsCaughtByTheVaultKey() {
        val e = runCatching {
            VaultSync("https://vault.example.net", Server(), "d").sync(email, "wrong", savedRefreshToken = "refresh-1")
        }.exceptionOrNull()
        assertTrue(e is VaultSync.WrongPassword)
    }

    @Test fun wrongPasswordWithoutTokenShowsTheServersMessage() {
        val e = runCatching { VaultSync("https://vault.example.net", Server(), "d").sync(email, "wrong", null) }.exceptionOrNull()
        assertTrue(e is VaultSync.Failure)
        assertEquals("Username or password is incorrect. Try again.", e!!.message)
    }

    @Test fun secondFactor() {
        val server = Server(requireTwoFactor = true)
        val sync = VaultSync("https://vault.example.net", server, "d")
        val e = runCatching { sync.sync(email, password, null) }.exceptionOrNull()
        assertTrue(e is VaultSync.TwoFactorRequired)
        assertEquals(listOf(0, 1), (e as VaultSync.TwoFactorRequired).providers)
        sync.sendEmailCode(email, password)
        val r = sync.sync(email, password, null, VaultSync.TwoFactor(VaultSync.PROVIDER_AUTHENTICATOR, " 123456 "))
        assertEquals(2, r.passkeyCount)
    }

    @Test fun addresses() {
        assertEquals("https://vault.example.net", VaultSync.normalize(" vault.example.net/ "))
        assertEquals("https://vault.example.net/bw", VaultSync.normalize("https://vault.example.net/bw/"))
        assertTrue(runCatching { VaultSync.normalize("http://vault.example.net") }.exceptionOrNull() is VaultSync.Failure)
    }

    @Test fun uploadAddsOnlyWhatTheVaultLacksAndReadsBack() {
        val server = Server()
        val sync = VaultSync("https://vault.example.net", server, "d")
        val session = sync.open(email, password, null)
        val inVault = Bitwarden.parse(sync.passkeys(session).exportJson).imported
        val mine = Bitwarden.parse(
            Bitwarden.export(listOf()).let {
                """{"items":[{"login":{"username":"sam","fido2Credentials":[{"credentialId":"9a8b7c6d-5e4f-3a2b-1c0d-0e1f2a3b4c5d",
                "keyValue":"${newPkcs8()}","rpId":"webauthn.example","userHandle":"aGFuZGxl","userName":"sam",
                "rpName":"Example","userDisplayName":"Sam","counter":"0","discoverable":"true","creationDate":""}]}}]}"""
            },
        ).imported
        val local = inVault + mine
        val have = inVault.map { it.credentialId }.toSet()
        val missing = local.filter { it.credentialId !in have }
        assertEquals(1, missing.size)
        val up = sync.upload(session, missing)
        assertEquals(missing, up.added)
        assertTrue(up.failed.isEmpty())
        // the server stored it encrypted: no plain text of the key in what was sent
        val stored = server.vault.getJSONArray("ciphers").let { it.getJSONObject(it.length() - 1) }
        assertTrue(!stored.toString().contains("webauthn.example"))
        // and it reads back as the same passkey
        val after = Bitwarden.parse(sync.sync(email, password, null).exportJson).imported
        assertEquals(3, after.size)
        val back = after.single { it.rpId == "webauthn.example" }
        assertEquals(missing[0].credentialId, back.credentialId)
        assertEquals(missing[0].keyValuePkcs8, back.keyValuePkcs8)
        assertEquals("Sam", back.userDisplayName)
    }
}
