package it.snel.passkeychain

import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.hybrid.HybridTransport
import it.snel.passkeychain.io.Bitwarden
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
}
