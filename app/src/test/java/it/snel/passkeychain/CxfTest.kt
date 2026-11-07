package it.snel.passkeychain

import it.snel.passkeychain.io.Cxf
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.Assertion
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Passkeys from a FIDO Credential Exchange Format (CXF 1.0) document. */
class CxfTest {

    private val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val credId = ByteArray(16) { (it * 7).toByte() }
    private val userHandle = ByteArray(12) { (it + 3).toByte() }

    /** A CXF export with one passkey and one password, shaped like the spec's header/accounts/items. */
    private fun document(key: String = B64.url(kp.private.encoded)): String = JSONObject().apply {
        put("version", JSONObject().put("major", 1).put("minor", 0))
        put("exporterRpId", "manager.example")
        put("exporterDisplayName", "Example Manager")
        put("timestamp", 1_800_000_000L)
        put("accounts", JSONArray().put(JSONObject().apply {
            put("id", "YWNjb3VudA"); put("username", "sam"); put("email", "sam@example.com")
            put("items", JSONArray()
                .put(JSONObject().apply {
                    put("id", "aXRlbTE"); put("title", "Example"); put("creationAt", 1_790_000_000L)
                    put("credentials", JSONArray().put(JSONObject().apply {
                        put("type", "passkey")
                        put("credentialId", B64.url(credId))
                        put("rpId", "example.com")
                        put("username", "sam@example.com")
                        put("userDisplayName", "Sam Jansen")
                        put("userHandle", B64.url(userHandle))
                        put("key", key)
                    }))
                })
                .put(JSONObject().apply {
                    put("id", "aXRlbTI"); put("title", "A password")
                    put("credentials", JSONArray().put(JSONObject().put("type", "basic-auth")))
                }))
        }))
    }.toString()

    @Test fun findsThePasskeyAndIgnoresTheRest() {
        assertTrue(Cxf.hasPasskeys(document()))
        val res = Cxf.parse(document())
        val pk = res.imported.single()
        assertTrue(res.skipped.isEmpty())
        assertEquals("example.com", pk.rpId)
        assertEquals("Example", pk.rpName)
        assertEquals("sam@example.com", pk.userName)
        assertEquals("Sam Jansen", pk.userDisplayName)
        assertArrayEquals(credId, B64.dUrl(pk.credentialId))
        assertArrayEquals(userHandle, B64.dUrl(pk.userHandle))
        assertTrue(pk.creationDate.startsWith("2026-"))
        assertTrue(pk.backedUp)
    }

    @Test fun theImportedKeySigns() {
        val pk = Cxf.parse(document()).imported.single()
        val cdh = ByteArray(32) { 1 }
        val r = Assertion.create(pk, "", "", clientDataHash = cdh)
        val ok = Signature.getInstance("SHA256withECDSA").run { initVerify(kp.public); update(r.authenticatorData + cdh); verify(r.signature) }
        assertTrue(ok)
    }

    @Test fun aBadKeyIsSkippedNotFatal() {
        val res = Cxf.parse(document(key = "c2VjcmV0"))
        assertTrue(res.imported.isEmpty())
        assertEquals(1, res.skipped.size)
    }

    @Test fun bitwardenFilesAreNotMistakenForCxf() {
        val bitwarden = """{"encrypted":false,"items":[{"login":{"fido2Credentials":[{"keyValue":"x","rpId":"a"}]}}]}"""
        assertTrue(!Cxf.hasPasskeys(bitwarden))
        assertTrue(!Cxf.hasPasskeys("not json"))
    }
}
