package it.snel.passkeychain

import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.hybrid.HybridTransport
import it.snel.passkeychain.io.KeePassXc
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
 * encodings, ES256 assertion signing, the FIDO QR digit packing, KeePassXC
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

    @Test fun keePassXcRoundTrip() {
        val (priv, _) = freshKey()
        val json = JSONObject().put(
            "fido2Credentials",
            org.json.JSONArray().put(
                JSONObject()
                    .put("credentialId", B64.std(ByteArray(20) { it.toByte() }))
                    .put("keyType", "public-key").put("keyAlgorithm", "ECDSA").put("keyCurve", "P-256")
                    .put("keyValue", toPem(priv.encoded))
                    .put("rpId", "login.microsoft.com").put("rpName", "Microsoft")
                    .put("userHandle", B64.std("lasjksdkjfhsdkj".toByteArray()))
                    .put("userName", "r.snel@asg.nl").put("userDisplayName", "Rik Snel")
                    .put("counter", "0").put("discoverable", "true")
            )
        ).toString()

        val imported = KeePassXc.parse(json)
        assertEquals(1, imported.imported.size)
        val pk = imported.imported[0]
        // canonical key must decode to the same private scalar
        assertEquals(priv.s, CredentialKey.decodePrivate(pk.keyValuePkcs8).s)

        // export then re-import must preserve the key and ids
        val exported = KeePassXc.export(listOf(pk))
        val again = KeePassXc.parse(exported).imported.single()
        assertEquals(pk.credentialId, again.credentialId)
        assertEquals(pk.userHandle, again.userHandle)
        assertEquals(CredentialKey.decodePrivate(pk.keyValuePkcs8).s, CredentialKey.decodePrivate(again.keyValuePkcs8).s)
    }

    @Test fun redactedKeyIsRejected() {
        val json = """{"fido2Credentials":[{"credentialId":"AAAA","keyValue":"secret","rpId":"x"}]}"""
        val res = KeePassXc.parse(json)
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
