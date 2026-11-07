package it.snel.passkeychain

import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.hybrid.CtapAuthenticator
import it.snel.passkeychain.hybrid.CtapAuthenticator.Decision
import it.snel.passkeychain.hybrid.HybridTransport
import it.snel.passkeychain.io.Argon2id
import it.snel.passkeychain.io.Bitwarden
import it.snel.passkeychain.io.BitwardenEncrypted
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.Assertion
import it.snel.passkeychain.webauthn.Cbor
import it.snel.passkeychain.webauthn.CredentialKey
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.util.Random

/**
 * Re-verifies on every CI run the correctness-critical logic that cannot be
 * exercised on this build machine (no Android build): key decoding across
 * encodings, ES256 assertion signing, the FIDO QR digit packing, Bitwarden
 * import/export round-trip, and the hybrid getAssertion assembly.
 */
class CredentialKeyTest {

    private fun freshKey(): Pair<ECPrivateKey, ECPublicKey> {
        val kpg = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val kp = kpg.generateKeyPair()
        return kp.private as ECPrivateKey to (kp.public as ECPublicKey)
    }

    private fun toPem(der: ByteArray): String {
        val b = B64.std(der)
        val sb = StringBuilder("-----BEGIN PRIVATE KEY-----\n")
        var i = 0; while (i < b.length) { sb.append(b, i, minOf(i + 64, b.length)).append('\n'); i += 64 }
        return sb.append("-----END PRIVATE KEY-----\n").toString()
    }

    private fun scalar(priv: ECPrivateKey): ByteArray {
        val b = priv.s.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }

    @Test fun decodesAllEncodingsToSameKey() {
        val (priv, _) = freshKey()
        val pem = toPem(priv.encoded)
        val b64pkcs8 = B64.std(priv.encoded)
        val b64urlRaw = B64.url(scalar(priv))
        for (enc in listOf(pem, b64pkcs8, b64urlRaw)) {
            val d = CredentialKey.decodePrivate(enc)
            assertEquals("scalar must match for encoding ${enc.take(12)}", priv.s, d.s)
        }
    }

    @Test fun assertionSignatureVerifies() {
        val (priv, pub) = freshKey()
        val pk = it.snel.passkeychain.model.Passkey(
            credentialId = B64.url(ByteArray(16) { it.toByte() }),
            keyValuePkcs8 = B64.std(priv.encoded),
            rpId = "login.microsoft.com",
            userHandle = B64.url(ByteArray(8) { (it + 1).toByte() }),
            userName = "r.snel@asg.nl",
        )
        val r = Assertion.create(pk, challengeB64Url = B64.url("hello".toByteArray()), origin = "https://login.microsoft.com")
        requireNotNull(r.clientDataJson)
        val cdHash = MessageDigest.getInstance("SHA-256").digest(r.clientDataJson)
        val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(pub); update(r.authenticatorData + cdHash) }
        assertTrue("assertion must verify", v.verify(r.signature))
        // rpIdHash is first 32 bytes of authData
        val rpHash = MessageDigest.getInstance("SHA-256").digest("login.microsoft.com".toByteArray())
        assertArrayEquals(rpHash, r.authenticatorData.copyOfRange(0, 32))
    }

    @Test fun assertionWithClientDataHashVerifies() {
        val (priv, pub) = freshKey()
        val pk = it.snel.passkeychain.model.Passkey(
            credentialId = B64.url(ByteArray(16)), keyValuePkcs8 = B64.std(priv.encoded),
            rpId = "example.com", userHandle = B64.url(ByteArray(4)),
        )
        val cdh = MessageDigest.getInstance("SHA-256").digest("browser-supplied".toByteArray())
        val r = Assertion.create(pk, "", "", clientDataHash = cdh)
        assertTrue(r.clientDataJson == null)
        val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(pub); update(r.authenticatorData + cdh) }
        assertTrue(v.verify(r.signature))
    }

    @Test fun fidoQrDigitPackingRoundTrips() {
        val rnd = Random(42)
        for (n in intArrayOf(1, 2, 3, 7, 8, 14, 16, 33, 49, 50, 64)) {
            val bytes = ByteArray(n).also { rnd.nextBytes(it) }
            val digits = bytesToDigits(bytes)
            assertArrayEquals("round trip for n=$n", bytes, FidoQr.digitsToBytes(digits))
        }
    }

    @Test fun fidoQrParsesSyntheticPayload() {
        // Shaped like a real Microsoft sign-in QR: map{0:pub33,1:secret16,2:2,3:time,4:false,5:"ga"}
        val pub = ByteArray(33) { 0x02 }
        val secret = ByteArray(16) { it.toByte() }
        val m = linkedMapOf<Any, Any>(0 to pub, 1 to secret, 2 to 2, 3 to 1_793_688_129L, 4 to false, 5 to "ga")
        val payload = Cbor.encode(m)
        val qr = "FIDO:/" + bytesToDigits(payload)
        assertTrue(FidoQr.isFidoQr(qr))
        val parsed = FidoQr.parse(qr)
        assertArrayEquals(pub, parsed.peerPublicKey)
        assertArrayEquals(secret, parsed.qrSecret)
        assertEquals("ga", parsed.hint)
    }

    /** One passkey as Bitwarden writes it: GUID credentialId, base64url key and user handle, string counters. */
    private fun bitwardenCredential(priv: ECPrivateKey, credentialId: String): JSONObject = JSONObject()
        .put("credentialId", credentialId)
        .put("keyType", "public-key").put("keyAlgorithm", "ECDSA").put("keyCurve", "P-256")
        .put("keyValue", B64.url(priv.encoded))
        .put("rpId", "login.microsoft.com")
        .put("userHandle", B64.url("lasjksdkjfhsdkj".toByteArray()))
        .put("userName", "r.snel@asg.nl")
        .put("counter", "0")
        .put("rpName", "Microsoft")
        .put("userDisplayName", "Rik Snel")
        .put("discoverable", "true")
        .put("creationDate", "2026-09-16T06:32:48.156Z")

    private fun bitwardenExport(vararg creds: JSONObject): String = JSONObject()
        .put("encrypted", false)
        .put("folders", org.json.JSONArray())
        .put("items", org.json.JSONArray().put(JSONObject()
            .put("type", 1).put("name", "Microsoft")
            .put("login", JSONObject()
                .put("username", "r.snel@asg.nl")
                .put("fido2Credentials", org.json.JSONArray().apply { creds.forEach { put(it) } }))))
        .toString()

    @Test fun bitwardenFullExportImports() {
        val (priv, _) = freshKey()
        val guid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        val res = Bitwarden.parse(bitwardenExport(bitwardenCredential(priv, guid)))
        assertEquals(1, res.imported.size)
        val pk = res.imported.single()
        // a GUID credentialId stands for its 16 bytes, in order
        assertArrayEquals(Bitwarden.credentialIdBytes(guid), B64.dUrl(pk.credentialId))
        assertEquals(0x0f.toByte(), B64.dUrl(pk.credentialId)[0])
        assertEquals(16, B64.dUrl(pk.credentialId).size)
        assertEquals(priv.s, CredentialKey.decodePrivate(pk.keyValuePkcs8).s)
        assertArrayEquals("lasjksdkjfhsdkj".toByteArray(), B64.dUrl(pk.userHandle))
        assertEquals("login.microsoft.com", pk.rpId)
        assertEquals("Rik Snel", pk.userDisplayName)
    }

    @Test fun bitwardenB64PrefixedCredentialId() {
        val (priv, _) = freshKey()
        val id = ByteArray(20) { (it * 7).toByte() }
        val pk = Bitwarden.parse(bitwardenExport(bitwardenCredential(priv, "b64." + B64.url(id)))).imported.single()
        assertArrayEquals(id, B64.dUrl(pk.credentialId))
    }

    @Test fun bitwardenRoundTrip() {
        val (priv, _) = freshKey()
        val guid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        val long = ByteArray(32) { it.toByte() }
        val pks = Bitwarden.parse(bitwardenExport(
            bitwardenCredential(priv, guid), bitwardenCredential(priv, "b64." + B64.url(long)).put("userName", "other"),
        )).imported
        val exported = Bitwarden.export(pks)
        // Bitwarden's own encodings: GUID or b64. id, base64url key, items with logins
        val items = JSONObject(exported).getJSONArray("items")
        val all = (0 until items.length()).flatMap { i ->
            val c = items.getJSONObject(i).getJSONObject("login").getJSONArray("fido2Credentials")
            (0 until c.length()).map { c.getJSONObject(it) }
        }
        assertEquals(setOf(guid, "b64." + B64.url(long)), all.map { it.getString("credentialId") }.toSet())
        all.forEach { c ->
            val k = c.getString("keyValue")
            assertTrue("keyValue must be base64url", k.none { it == '=' || it == '+' || it == '/' } && !k.contains("BEGIN"))
            assertEquals("0", c.getString("counter"))
            assertEquals("true", c.getString("discoverable"))
        }
        val again = Bitwarden.parse(exported).imported
        assertEquals(pks.map { it.credentialId }.toSet(), again.map { it.credentialId }.toSet())
        again.forEach { assertEquals(priv.s, CredentialKey.decodePrivate(it.keyValuePkcs8).s) }
    }

    @Test fun pastedSnippetImports() {
        // just the "fido2Credentials" part of an export, like the original passkey.txt
        val (priv, _) = freshKey()
        val snippet = "\"fido2Credentials\": [" + bitwardenCredential(priv, "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0") + "]"
        assertEquals(1, Bitwarden.parse(snippet).imported.size)
    }

    @Test fun olderPemExportStillImports() {
        val (priv, _) = freshKey()
        val json = JSONObject().put("fido2Credentials", org.json.JSONArray().put(
            bitwardenCredential(priv, B64.std(ByteArray(20) { it.toByte() })).put("keyValue", toPem(priv.encoded)),
        )).toString()
        val pk = Bitwarden.parse(json).imported.single()
        assertEquals(priv.s, CredentialKey.decodePrivate(pk.keyValuePkcs8).s)
        assertArrayEquals(ByteArray(20) { it.toByte() }, B64.dUrl(pk.credentialId))
    }

    @Test fun redactedKeyIsRejected() {
        val json = """{"items":[{"login":{"fido2Credentials":[{"credentialId":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX","keyValue":"secret","rpId":"x"}]}}]}"""
        val res = Bitwarden.parse(json)
        assertEquals(0, res.imported.size)
        assertEquals(1, res.skipped.size)
    }

    @Test fun hkdfIsDeterministicAndSized() {
        val a = HybridTransport.hkdf("ikm".toByteArray(), ByteArray(32), byteArrayOf(1), 32)
        val b = HybridTransport.hkdf("ikm".toByteArray(), ByteArray(32), byteArrayOf(1), 32)
        assertArrayEquals(a, b)
        assertEquals(32, a.size)
        assertEquals(16, HybridTransport.hkdf("ikm".toByteArray(), ByteArray(32), byteArrayOf(2), 16).size)
    }

    @Test fun hybridGetAssertionBuildsSignedResponse() {
        val (priv, pub) = freshKey()
        val pk = it.snel.passkeychain.model.Passkey(
            credentialId = B64.url(ByteArray(16) { it.toByte() }), keyValuePkcs8 = B64.std(priv.encoded),
            rpId = "login.microsoft.com", userHandle = B64.url(ByteArray(8)),
        )
        val clientDataHash = MessageDigest.getInstance("SHA-256").digest("cdh".toByteArray())
        // CTAP2 getAssertion: 0x02 || cbor{1:rpId, 2:clientDataHash}
        val params = Cbor.encode(linkedMapOf<Any, Any>(1 to "login.microsoft.com", 2 to clientDataHash))
        val req = byteArrayOf(0x02) + params
        val transport = HybridTransport(
            object : HybridTransport.BleAdvertiser { override fun advertise(serviceUuid: java.util.UUID, payload: ByteArray) {}; override fun stop() {} },
            object : HybridTransport.TunnelClient {
                override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel =
                    throw UnsupportedOperationException()
            },
        )
        val resp = transport.buildGetAssertionResponse(req, pk)
        assertEquals(0x00.toByte(), resp[0]) // CTAP2_OK
        @Suppress("UNCHECKED_CAST")
        val map = Cbor.decode(resp.copyOfRange(1, resp.size)) as Map<Any?, Any?>
        val authData = (map[2L] ?: map[2]) as ByteArray
        val sig = (map[3L] ?: map[3]) as ByteArray
        val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(pub); update(authData + clientDataHash) }
        assertTrue("hybrid assertion signature must verify", v.verify(sig))
    }

    // Reference encoder matching FidoQr.digitsToBytes (7 bytes -> 17 digits LE + partials)
    private fun bytesToDigits(b: ByteArray): String {
        val tbl = mapOf(1 to 3, 2 to 5, 3 to 8, 4 to 10, 5 to 13, 6 to 15, 7 to 17)
        val sb = StringBuilder()
        var i = 0
        while (i < b.size) {
            val n = minOf(7, b.size - i)
            var v = 0L
            for (j in n - 1 downTo 0) v = (v shl 8) or (b[i + j].toLong() and 0xFF)
            sb.append(v.toString().padStart(tbl[n]!!, '0'))
            i += n
        }
        return sb.toString()
    }

    // ---- CTAP: decide first, sign after -----------------------------------------

    private fun pkWith(priv: ECPrivateKey, id: ByteArray, rpId: String = "login.microsoft.com", user: String = "r.snel@asg.nl") =
        it.snel.passkeychain.model.Passkey(
            credentialId = B64.url(id), keyValuePkcs8 = B64.std(priv.encoded), rpId = rpId,
            userHandle = B64.url(user.toByteArray()), userName = user,
        )

    private fun getAssertion(rpId: String, cdh: ByteArray, allow: List<ByteArray>): ByteArray {
        val params = linkedMapOf<Any, Any>(1 to rpId, 2 to cdh)
        if (allow.isNotEmpty()) params[3] = allow.map { linkedMapOf<Any, Any>("id" to it, "type" to "public-key") }
        return byteArrayOf(0x02) + Cbor.encode(params)
    }

    private val cdh = MessageDigest.getInstance("SHA-256").digest("challenge".toByteArray())

    @Test fun refusalSignsNothing() {
        var asked = 0
        val req = getAssertion("login.microsoft.com", cdh, emptyList())
        assertArrayEquals(byteArrayOf(0x27), CtapAuthenticator.handle(req) { asked++; Decision.Denied })
        assertArrayEquals(byteArrayOf(0x2E), CtapAuthenticator.handle(req) { asked++; Decision.NoCredentials })
        assertEquals(2, asked)
    }

    @Test fun requestIsParsedBeforeAnyChoice() {
        val a = ByteArray(16) { 1 }; val b = ByteArray(16) { 2 }
        var seen: CtapAuthenticator.GetAssertionRequest? = null
        CtapAuthenticator.handle(getAssertion("login.microsoft.com", cdh, listOf(a, b))) { seen = it; Decision.Denied }
        val r = seen!!
        assertEquals("login.microsoft.com", r.rpId)
        assertArrayEquals(cdh, r.clientDataHash)
        assertEquals(2, r.allowList.size)
        assertArrayEquals(b, r.allowList[1])
    }

    @Test fun candidatesFollowSiteAndAllowList() {
        val (priv, _) = freshKey()
        val mine = pkWith(priv, ByteArray(16) { 1 })
        val other = pkWith(priv, ByteArray(16) { 2 }, user = "other@asg.nl")
        val elsewhere = pkWith(priv, ByteArray(16) { 1 }, rpId = "github.com")
        val withList = CtapAuthenticator.parseGetAssertion(getAssertion("login.microsoft.com", cdh, listOf(ByteArray(16) { 1 })))
        assertEquals(listOf(true, false, false), listOf(mine, other, elsewhere).map { withList.accepts(it) })
        val noList = CtapAuthenticator.parseGetAssertion(getAssertion("login.microsoft.com", cdh, emptyList()))
        assertEquals(listOf(true, true, false), listOf(mine, other, elsewhere).map { noList.accepts(it) })
    }

    @Test fun chosenPasskeySignsWithItsOwnId() {
        val (priv1, pub1) = freshKey(); val (priv2, pub2) = freshKey()
        val first = pkWith(priv1, ByteArray(16) { 1 }); val second = pkWith(priv2, ByteArray(16) { 2 }, user = "other@asg.nl")
        val req = getAssertion("login.microsoft.com", cdh, listOf(ByteArray(16) { 1 }, ByteArray(16) { 2 }))
        val resp = CtapAuthenticator.handle(req) { Decision.Sign(second) }
        assertEquals(0x00.toByte(), resp[0])
        @Suppress("UNCHECKED_CAST")
        val m = Cbor.decode(resp.copyOfRange(1, resp.size)) as Map<Any?, Any?>
        @Suppress("UNCHECKED_CAST")
        val cred = (m[1L] ?: m[1]) as Map<Any?, Any?>
        assertArrayEquals(ByteArray(16) { 2 }, cred["id"] as ByteArray)
        val authData = (m[2L] ?: m[2]) as ByteArray; val sig = (m[3L] ?: m[3]) as ByteArray
        assertTrue(Signature.getInstance("SHA256withECDSA").apply { initVerify(pub2); update(authData + cdh) }.verify(sig))
        assertTrue(!Signature.getInstance("SHA256withECDSA").apply { initVerify(pub1); update(authData + cdh) }.verify(sig))
        assertTrue("no user entity when the site named the credential", (m[4L] ?: m[4]) == null)
    }

    @Test fun usernamelessSignInReturnsUserHandle() {
        val (priv, _) = freshKey()
        val pk = pkWith(priv, ByteArray(16) { 1 })
        val resp = CtapAuthenticator.handle(getAssertion("login.microsoft.com", cdh, emptyList())) { Decision.Sign(pk) }
        @Suppress("UNCHECKED_CAST")
        val m = Cbor.decode(resp.copyOfRange(1, resp.size)) as Map<Any?, Any?>
        @Suppress("UNCHECKED_CAST")
        val user = (m[4L] ?: m[4]) as Map<Any?, Any?>
        assertArrayEquals("r.snel@asg.nl".toByteArray(), user["id"] as ByteArray)
    }

    @Test(expected = IllegalArgumentException::class)
    fun passkeyForAnotherSiteIsNeverUsed() {
        val (priv, _) = freshKey()
        val wrong = pkWith(priv, ByteArray(16) { 1 }, rpId = "github.com")
        CtapAuthenticator.handle(getAssertion("login.microsoft.com", cdh, emptyList())) { Decision.Sign(wrong) }
    }

    // ---- Bitwarden password-protected (encrypted) export ---------------------------

    private fun ub(vararg x: Int) = ByteArray(x.size) { x[it].toByte() }

    /** Known answers from bitwarden/sdk-internal (crates/bitwarden-crypto/src/keys/kdf.rs, util.rs). */
    @Test fun bitwardenKdfVectors() {
        val pw = "67t9b5g67\$%Dh89n".toByteArray()
        assertArrayEquals(
            ub(31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75),
            BitwardenEncrypted.pbkdf2Sha256(pw, "test_key".toByteArray(), 10000, 32),
        )
        assertArrayEquals(
            ub(207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147, 237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242),
            Argon2id.hash(pw, MessageDigest.getInstance("SHA-256").digest("test_key".toByteArray()), 4, 32 * 1024, 2, 32),
        )
        val prk = ub(23, 152, 120, 41, 214, 16, 156, 133, 71, 226, 178, 135, 208, 255, 66, 101, 189, 70, 173, 30, 39, 215, 175, 236, 38, 180, 180, 62, 196, 4, 159, 70)
        assertArrayEquals(
            ub(6, 114, 42, 38, 87, 231, 30, 109, 30, 255, 104, 129, 255, 94, 92, 108, 124, 145, 215, 208, 17, 60, 135, 22, 70, 158, 40, 53, 45, 182, 8, 63,
                65, 87, 239, 234, 185, 227, 153, 122, 115, 205, 144, 56, 102, 149, 92, 139, 217, 102, 119, 57, 37, 57, 251, 178, 18, 52, 94, 77, 132, 215, 239, 100),
            BitwardenEncrypted.hkdfExpand(prk, "info".toByteArray(), 64),
        )
    }

    @Test fun encryptedExportRoundTrip() {
        val (priv, _) = freshKey()
        val inner = bitwardenExport(bitwardenCredential(priv, "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"))
        val file = BitwardenEncrypted.encrypt(inner, "corréct horse", iterations = 5000) // fast for the test
        assertTrue(BitwardenEncrypted.isEncrypted(file) && BitwardenEncrypted.isPasswordProtected(file))
        assertTrue("nothing readable in the file", !file.contains("login.microsoft.com") && !file.contains("r.snel"))
        val doc = JSONObject(file)
        assertEquals(0, doc.getInt("kdfType"))
        assertTrue(doc.getString("data").startsWith("2."))
        val back = BitwardenEncrypted.decrypt(file, "corréct horse")
        assertEquals(inner, back)
        assertEquals(priv.s, CredentialKey.decodePrivate(Bitwarden.parse(back).imported.single().keyValuePkcs8).s)
    }

    @Test(expected = BitwardenEncrypted.WrongPassword::class)
    fun encryptedExportWrongPassword() {
        BitwardenEncrypted.decrypt(BitwardenEncrypted.encrypt("{}", "right password", iterations = 5000), "wrong password")
    }

    @Test fun tamperedDataIsRejected() {
        val doc = JSONObject(BitwardenEncrypted.encrypt("{\"items\":[]}", "pw-12345", iterations = 5000))
        val parts = doc.getString("data").removePrefix("2.").split("|").toMutableList()
        val ct = java.util.Base64.getDecoder().decode(parts[1]); ct[0] = (ct[0].toInt() xor 1).toByte()
        parts[1] = java.util.Base64.getEncoder().encodeToString(ct)
        doc.put("data", "2." + parts.joinToString("|"))
        val err = runCatching { BitwardenEncrypted.decrypt(doc.toString(), "pw-12345") }.exceptionOrNull()
        assertTrue("authentication must fail, not the password check: $err", err != null && err !is BitwardenEncrypted.WrongPassword)
    }

    @Test fun accountRestrictedAndHostileKdfAreRefused() {
        val restricted = """{"encrypted":true,"passwordProtected":false,"encKeyValidation_DO_NOT_EDIT":"2.x|y|z","data":"2.x|y|z"}"""
        assertTrue(BitwardenEncrypted.isEncrypted(restricted) && !BitwardenEncrypted.isPasswordProtected(restricted))
        assertTrue(runCatching { BitwardenEncrypted.decrypt(restricted, "x") }.exceptionOrNull() is BitwardenEncrypted.Unsupported)
        for (kdf in listOf(
            """"kdfType":0,"kdfIterations":100""",
            """"kdfType":1,"kdfIterations":3,"kdfMemory":4096,"kdfParallelism":4""",
            """"kdfType":7,"kdfIterations":3""",
        )) {
            val f = """{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==",$kdf,"encKeyValidation_DO_NOT_EDIT":"2.x|y|z","data":"2.x|y|z"}"""
            assertTrue(kdf, runCatching { BitwardenEncrypted.decrypt(f, "x") }.exceptionOrNull() is BitwardenEncrypted.Unsupported)
        }
    }
}
