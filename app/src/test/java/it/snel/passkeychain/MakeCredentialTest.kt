package it.snel.passkeychain

import it.snel.passkeychain.hybrid.CtapAuthenticator
import it.snel.passkeychain.hybrid.CtapAuthenticator.CreateDecision
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.Cbor
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/** Creating a passkey over the hybrid transport (CTAP2 authenticatorMakeCredential). */
class MakeCredentialTest {

    private val clientDataHash = MessageDigest.getInstance("SHA-256").digest("create".toByteArray())
    private val userId = ByteArray(8) { (it + 1).toByte() }

    private fun request(rpId: String = "example.com", algs: List<Long> = listOf(-7L), exclude: List<ByteArray> = emptyList()): ByteArray =
        byteArrayOf(0x01) + Cbor.encode(mapOf<Any, Any>(
            1 to clientDataHash,
            2 to mapOf<Any, Any>("id" to rpId, "name" to "Example"),
            3 to mapOf<Any, Any>("id" to userId, "name" to "sam@example.com", "displayName" to "Sam Jansen"),
            4 to algs.map { mapOf<Any, Any>("alg" to it, "type" to "public-key") },
            5 to exclude.map { mapOf<Any, Any>("id" to it, "type" to "public-key") },
            7 to mapOf<Any, Any>("rk" to true),
        ))

    /** A creator that answers [decision] and remembers what it stored. */
    private class FakeCreator(val decision: (CtapAuthenticator.MakeCredentialRequest) -> CreateDecision) : CtapAuthenticator.Creator {
        val stored = mutableListOf<Passkey>()
        var asked = 0
        override fun approve(request: CtapAuthenticator.MakeCredentialRequest): CreateDecision { asked++; return decision(request) }
        override fun store(passkey: Passkey) { stored += passkey }
    }

    private fun noChoice() = CtapAuthenticator.Chooser { error("not a sign-in") }
    private fun status(resp: ByteArray) = resp[0].toInt() and 0xFF

    @Test fun createsAPasskeyThatCanSignIn() {
        val creator = FakeCreator { CreateDecision.Create }
        val resp = CtapAuthenticator.handle(request(), creator, noChoice())
        assertEquals(CtapAuthenticator.CTAP2_OK, status(resp))
        val pk = creator.stored.single()
        assertEquals("example.com", pk.rpId)
        assertEquals("sam@example.com", pk.userName)
        assertEquals(B64.url(userId), pk.userHandle)
        assertTrue("a new passkey has no copy elsewhere yet", !pk.backedUp)

        @Suppress("UNCHECKED_CAST")
        val att = Cbor.decode(resp.copyOfRange(1, resp.size)) as Map<Any?, Any?>
        assertEquals("none", att[1L])
        assertTrue((att[3L] as Map<*, *>).isEmpty())
        val authData = att[2L] as ByteArray
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest("example.com".toByteArray()), authData.copyOfRange(0, 32))
        assertEquals("flags UP UV BE AT, no BS", 0x4D, authData[32].toInt() and 0xFF)
        assertArrayEquals(ByteArray(4), authData.copyOfRange(33, 37))   // counter 0
        assertArrayEquals(ByteArray(16), authData.copyOfRange(37, 53))  // aaguid
        val idLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        val id = authData.copyOfRange(55, 55 + idLen)
        assertArrayEquals(B64.dUrl(pk.credentialId), id)
        @Suppress("UNCHECKED_CAST")
        val cose = Cbor.decode(authData.copyOfRange(55 + idLen, authData.size)) as Map<Any?, Any?>
        assertEquals(2L, cose[1L]); assertEquals(-7L, cose[3L]); assertEquals(1L, cose[-1L])

        // the site keeps that public key; a later sign-in with the stored passkey must verify against it
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(
            ECPoint(BigInteger(1, cose[-2L] as ByteArray), BigInteger(1, cose[-3L] as ByteArray)), params))
        val cdh = MessageDigest.getInstance("SHA-256").digest("login".toByteArray())
        val get = byteArrayOf(0x02) + Cbor.encode(mapOf<Any, Any>(1 to "example.com", 2 to cdh))
        val sign = CtapAuthenticator.handle(get) { CtapAuthenticator.Decision.Sign(pk) }
        @Suppress("UNCHECKED_CAST")
        val m = Cbor.decode(sign.copyOfRange(1, sign.size)) as Map<Any?, Any?>
        val signedAuthData = m[2L] as ByteArray
        assertEquals("sign-in flags UP UV BE, still no BS", 0x0D, signedAuthData[32].toInt() and 0xFF)
        val ok = Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(signedAuthData + cdh); verify(m[3L] as ByteArray) }
        assertTrue("the signature verifies with the attested public key", ok)
    }

    @Test fun chromesProbeNeverCreatesAPasskey() {
        val creator = FakeCreator { CreateDecision.Create }
        val resp = CtapAuthenticator.handle(request(rpId = ".dummy"), creator, noChoice())
        assertEquals(CtapAuthenticator.CTAP2_ERR_NO_CREDENTIALS, status(resp))
        assertEquals(0, creator.asked)
        assertTrue(creator.stored.isEmpty())
    }

    @Test fun withoutACreatorNothingIsCreated() {
        assertEquals(CtapAuthenticator.CTAP2_ERR_NO_CREDENTIALS, status(CtapAuthenticator.handle(request(), chooser = noChoice())))
    }

    @Test fun excludedAccountGetsNoSecondPasskey() {
        val existing = Passkey(credentialId = B64.url(ByteArray(16) { 9 }), keyValuePkcs8 = "", rpId = "example.com", userHandle = "")
        val creator = FakeCreator { r -> if (r.excludes(existing)) CreateDecision.Excluded else CreateDecision.Create }
        val resp = CtapAuthenticator.handle(request(exclude = listOf(ByteArray(16) { 9 })), creator, noChoice())
        assertEquals(CtapAuthenticator.CTAP2_ERR_CREDENTIAL_EXCLUDED, status(resp))
        assertTrue(creator.stored.isEmpty())
    }

    @Test fun onlyEs256IsMade() {
        val creator = FakeCreator { CreateDecision.Create }
        val resp = CtapAuthenticator.handle(request(algs = listOf(-257L)), creator, noChoice()) // RS256 only
        assertEquals(CtapAuthenticator.CTAP2_ERR_UNSUPPORTED_ALGORITHM, status(resp))
        assertEquals(0, creator.asked)
    }

    @Test fun refusalCreatesNothing() {
        val creator = FakeCreator { CreateDecision.Denied }
        assertEquals(CtapAuthenticator.CTAP2_ERR_OPERATION_DENIED, status(CtapAuthenticator.handle(request(), creator, noChoice())))
        assertTrue(creator.stored.isEmpty())
    }

    @Test fun whichRequestsEndTheExchange() {
        assertTrue(CtapAuthenticator.isFinal(request(), canCreate = true))
        assertTrue(!CtapAuthenticator.isFinal(request(rpId = ".dummy"), canCreate = true))
        assertTrue(!CtapAuthenticator.isFinal(request(), canCreate = false))
        assertTrue(!CtapAuthenticator.isFinal(byteArrayOf(0x04), canCreate = true))
        assertTrue(CtapAuthenticator.isFinal(byteArrayOf(0x02, 0xA0.toByte()), canCreate = false))
    }
}
