package it.snel.passkeychain.util

import java.util.Base64

/**
 * Base64 helpers built on java.util.Base64 (available on API 26+, and our
 * minSdk is 28). Using the JDK codec instead of android.util.Base64 keeps the
 * crypto/import code runnable in plain JVM unit tests, so CI re-verifies it on
 * every build.
 */
object B64 {
    /** Standard base64, padded, single line. */
    fun std(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    /** URL-safe base64, no padding (WebAuthn id/userHandle form). */
    fun url(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    /** Decode standard base64, tolerating whitespace and missing padding. */
    fun dStd(s: String): ByteArray = Base64.getMimeDecoder().decode(pad(stripWs(s)))

    /** Decode url-safe base64, tolerating missing padding. */
    fun dUrl(s: String): ByteArray = Base64.getUrlDecoder().decode(stripWs(s).trimEnd('='))

    /** Decode either variant, chosen by alphabet. */
    fun any(s: String): ByteArray {
        val t = stripWs(s)
        return if (t.contains('-') || t.contains('_')) dUrl(t) else dStd(t)
    }

    private fun stripWs(s: String) = s.replace(Regex("\\s"), "")
    private fun pad(s: String): String {
        val m = s.length % 4
        return if (m == 0) s else s + "=".repeat(4 - m)
    }
}
