package it.snel.passkeychain.hybrid

import it.snel.passkeychain.webauthn.Cbor

/**
 * Decodes the `FIDO:/…` QR shown by a relying party for the cross-device
 * (hybrid / caBLE v2) flow — the QR in the Microsoft sign-in screenshot.
 *
 * Wire format (Chromium `v2_handshake.cc`):
 *   "FIDO:/" + decimal digits, where the digits are a base-10 packing of a
 *   byte string: every 7 bytes are encoded as a 17-digit little-endian number;
 *   a trailing partial chunk follows the table {1B:3d, 2B:5d, 3B:8d, 4B:10d,
 *   5B:13d, 6B:15d}. The byte string is a CBOR map:
 *     0: compressed P-256 public key (33 bytes)  -- the browser's identity key
 *     1: QR secret (16 bytes)
 *     2: number of assigned tunnel-server domains the browser knows
 *     3: current unix time (seconds)
 *     4: "can the phone do state-assisted transactions" (bool, optional)
 *     5: operation hint, "ga" (getAssertion) or "mc" (makeCredential)
 */
data class FidoQr(
    val peerPublicKey: ByteArray,   // 33-byte compressed point
    val qrSecret: ByteArray,        // 16 bytes
    val knownDomainCount: Int,
    val timestamp: Long,
    val stateAssisted: Boolean,
    val hint: String,
) {
    companion object {
        private const val PREFIX = "FIDO:/"

        fun isFidoQr(text: String): Boolean = text.trim().startsWith(PREFIX)

        fun parse(text: String): FidoQr {
            val t = text.trim()
            require(t.startsWith(PREFIX)) { "not a FIDO hybrid QR" }
            val digits = t.substring(PREFIX.length)
            require(digits.isNotEmpty() && digits.all { it.isDigit() }) { "malformed FIDO QR payload" }
            val bytes = digitsToBytes(digits)

            @Suppress("UNCHECKED_CAST")
            val map = Cbor.decode(bytes) as Map<Any?, Any?>
            fun bstr(k: Int) = map[k.toLong()] as? ByteArray ?: map[k] as ByteArray
            fun lng(k: Int) = (map[k.toLong()] ?: map[k]) as? Long
            fun str(k: Int) = (map[k.toLong()] ?: map[k]) as? String

            val pub = bstr(0)
            val secret = bstr(1)
            require(pub.size == 33) { "unexpected public key length ${pub.size}" }
            require(secret.size == 16) { "unexpected QR secret length ${secret.size}" }
            return FidoQr(
                peerPublicKey = pub,
                qrSecret = secret,
                knownDomainCount = (lng(2) ?: 0L).toInt(),
                timestamp = lng(3) ?: 0L,
                stateAssisted = (map[4L] ?: map[4]) == true,
                hint = str(5) ?: "ga",
            )
        }

        // digit-chunk length -> number of bytes it encodes (little-endian)
        private val CHUNK_BYTES = mapOf(3 to 1, 5 to 2, 8 to 3, 10 to 4, 13 to 5, 15 to 6, 17 to 7)

        /** Inverse of Chromium's BytesToDigits: chunks of 17 digits -> 7 bytes LE (+ partial). */
        fun digitsToBytes(digits: String): ByteArray {
            val out = ArrayList<Byte>(digits.length)
            var i = 0
            while (i < digits.length) {
                val remaining = digits.length - i
                val take = if (remaining >= 17) 17 else remaining
                val nBytes = CHUNK_BYTES[take]
                    ?: throw IllegalArgumentException("invalid trailing digit chunk of $take")
                var v = digits.substring(i, i + take).toLong()
                repeat(nBytes) { out.add((v and 0xFF).toByte()); v = v shr 8 }
                i += take
            }
            return out.toByteArray()
        }
    }

    override fun equals(other: Any?): Boolean =
        other is FidoQr && peerPublicKey.contentEquals(other.peerPublicKey) && qrSecret.contentEquals(other.qrSecret)
    override fun hashCode(): Int = peerPublicKey.contentHashCode() * 31 + qrSecret.contentHashCode()
}
