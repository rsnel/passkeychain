package it.snel.passkeychain.webauthn

import it.snel.passkeychain.util.B64
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Decodes an imported P-256 private key from the several encodings a passkey
 * exporter might use, and signs WebAuthn assertions with it.
 *
 * This is the Kotlin mirror of the logic verified in the standalone JDK proof
 * (all three decode paths + ES256 assertion signing + COSE_Key), and it is
 * re-verified on every CI run by CredentialKeyTest.
 *
 * Note: this app *uses* (asserts with) existing passkeys; it does not *register*
 * new ones, so deriving a public key from a bare private scalar is never needed.
 * The public key is only produced when it is already available (e.g. for a COSE
 * blob in tooling/tests).
 */
object CredentialKey {

    private fun p256Params(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)

    /** Accepts PEM PKCS#8, base64(PKCS#8 DER), or base64/base64url raw 32-byte scalar. */
    fun decodePrivate(keyValue: String): ECPrivateKey {
        val t = keyValue.trim()
        if (t.contains("BEGIN")) {
            val body = t.replace(Regex("-----[A-Z ]+-----"), "").replace(Regex("\\s"), "")
            return fromPkcs8(B64.dStd(body))
        }
        val raw = B64.any(t)
        if (raw.size == 32) return fromScalar(BigInteger(1, raw))
        return runCatching { fromPkcs8(raw) }
            .getOrElse { throw IllegalArgumentException("unrecognised keyValue encoding (len=${raw.size})") }
    }

    /** Normalises any accepted encoding to base64(PKCS#8 DER) for canonical storage. */
    fun toCanonicalPkcs8(keyValue: String): String {
        val priv = decodePrivate(keyValue)
        return B64.std(priv.encoded)
    }

    /** ES256 signature (DER-encoded ECDSA) over [data] — exactly what WebAuthn expects. */
    fun signEs256(priv: ECPrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(data); sign() }

    /** COSE_Key (EC2 / ES256 / P-256). Only used where a public key is already known. */
    fun coseEs256(pub: ECPublicKey): ByteArray {
        val x = fixed(pub.w.affineX, 32)
        val y = fixed(pub.w.affineY, 32)
        val m = LinkedHashMap<Any, Any>()
        m[1] = 2       // kty: EC2
        m[3] = -7      // alg: ES256
        m[-1] = 1      // crv: P-256
        m[-2] = x
        m[-3] = y
        return Cbor.encode(m)
    }

    // ---- helpers ------------------------------------------------------------
    private fun fromPkcs8(der: ByteArray): ECPrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der)) as ECPrivateKey

    private fun fromScalar(d: BigInteger): ECPrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(d, p256Params())) as ECPrivateKey

    private fun fixed(v: BigInteger, len: Int): ByteArray {
        val b = v.toByteArray()
        if (b.size == len) return b
        val r = ByteArray(len)
        if (b.size > len) System.arraycopy(b, b.size - len, r, 0, len)
        else System.arraycopy(b, 0, r, len - b.size, b.size)
        return r
    }
}
