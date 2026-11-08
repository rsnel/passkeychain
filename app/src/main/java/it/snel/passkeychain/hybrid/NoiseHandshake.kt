package it.snel.passkeychain.hybrid

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The responder side of the caBLE v2 Noise handshake for QR sign-ins,
 * Noise_KNpsk0_P256_AESGCM_SHA256 (docs/PROTOCOL.md, sections 6 and 7).
 * Pure JVM code: no network, no Android, so it can be unit-tested.
 *
 *   h = ck = protocol name padded to 32 bytes
 *   MixHash([0x01]); MixHash(peerIdentity65); MixKeyAndHash(psk)
 *   -> e                     msg1 from the browser: e_pub (65) || tag (16)
 *   <- e, ee, se             msg2 from us:          e_pub (65) || tag (16)
 *   Split -> (k1, k2): we receive with k1 and send with k2
 *
 * [peerIdentity65] is the browser's static key from the QR, uncompressed;
 * [ephemeral] is our P-256 key pair for this handshake (fresh unless a test
 * supplies one); [log] receives every intermediate value (for debug logging).
 */
class NoiseHandshake(
    private val peerIdentity65: ByteArray,
    psk: ByteArray,
    private val ephemeral: KeyPair = newEphemeral(),
    private val log: (String) -> Unit = {},
) {
    /** The handshake's outcome: msg2 to send, and the transport keys. */
    class Result(val msg2: ByteArray, val receiveKey: ByteArray, val sendKey: ByteArray, val handshakeHash: ByteArray)

    /** msg1 was malformed or did not authenticate (wrong psk, wrong QR, or not from the browser). */
    class Failed(message: String, cause: Throwable? = null) : Exception(message, cause)

    private var h: ByteArray
    private var ck: ByteArray
    private var k = ByteArray(32)
    private var used = false

    init {
        require(peerIdentity65.size == 65 && isOnCurve(peerIdentity65)) { "peer identity must be an uncompressed P-256 point" }
        require(psk.size == 32) { "psk must be 32 bytes" }
        val name = PROTOCOL_NAME.toByteArray(Charsets.US_ASCII)
        h = name.copyOf(32)
        ck = h.copyOf()
        mixHash(byteArrayOf(PROLOGUE))
        mixHash(peerIdentity65)
        mixKeyAndHash(psk)
        log("init: peerIdentity65 = ${hex(peerIdentity65)}")
        log("init: psk = ${hex(psk)}")
        log("init: after MixKeyAndHash(psk) h = ${hex(h)} ck = ${hex(ck)} k = ${hex(k)}")
    }

    /** Reads [msg1] and returns msg2 and the transport keys. Can be used once. */
    fun respond(msg1: ByteArray): Result {
        check(!used) { "a handshake can be run once" }
        used = true
        log("msg1 ${msg1.size} bytes: ${hex(msg1)}")
        if (msg1.size < P256_POINT + TAG) throw Failed("msg1 too short: ${msg1.size} bytes")
        val ePubI = msg1.copyOfRange(0, P256_POINT)
        if (!isOnCurve(ePubI)) throw Failed("The computer sent an invalid key")

        // -> e (psk handshake: MixHash and MixKey), then the empty payload
        mixHash(ePubI)
        mixKey(ePubI)
        val payload = try {
            decryptAndHash(msg1.copyOfRange(P256_POINT, msg1.size))
        } catch (e: AEADBadTagException) {
            throw Failed("msg1 did not authenticate (wrong psk or QR key?)", e)
        }
        log("msg1 ok, payload ${payload.size} bytes (expected 0); h = ${hex(h)}")

        // <- e, ee, se
        val ePubR = uncompressed(ephemeral.public as ECPublicKey)
        mixHash(ePubR)
        mixKey(ePubR)
        mixKey(ecdh(ephemeral.private as ECPrivateKey, ePubI))           // ee
        mixKey(ecdh(ephemeral.private as ECPrivateKey, peerIdentity65))  // se: browser static x our ephemeral
        val msg2 = ePubR + encryptAndHash(ByteArray(0))
        log("msg2 ${msg2.size} bytes: ${hex(msg2)}")

        val split = hkdf(ByteArray(0), ck, 64)
        val k1 = split.copyOfRange(0, 32)
        val k2 = split.copyOfRange(32, 64)
        log("split: receive key = ${hex(k1)} send key = ${hex(k2)} h = ${hex(h)}")
        return Result(msg2, receiveKey = k1, sendKey = k2, handshakeHash = h.copyOf())
    }

    private fun mixHash(data: ByteArray) {
        h = MessageDigest.getInstance("SHA-256").digest(h + data)
    }

    private fun mixKey(ikm: ByteArray) {
        val out = hkdf(ikm, ck, 64)
        ck = out.copyOfRange(0, 32)
        k = out.copyOfRange(32, 64)
    }

    private fun mixKeyAndHash(ikm: ByteArray) {
        val out = hkdf(ikm, ck, 96)
        ck = out.copyOfRange(0, 32)
        mixHash(out.copyOfRange(32, 64))
        k = out.copyOfRange(64, 96)
    }

    // Every key in this handshake is used for one AEAD operation only (each
    // MixKey resets the counter), so the nonce is always 12 zero bytes.
    private fun encryptAndHash(plaintext: ByteArray): ByteArray =
        gcm(Cipher.ENCRYPT_MODE, k, ByteArray(12), plaintext, aad = h).also { mixHash(it) }

    private fun decryptAndHash(ciphertext: ByteArray): ByteArray =
        gcm(Cipher.DECRYPT_MODE, k, ByteArray(12), ciphertext, aad = h).also { mixHash(ciphertext) }

    companion object {
        const val PROTOCOL_NAME = "Noise_KNpsk0_P256_AESGCM_SHA256"
        /** 0x01: QR-initiated (KNpsk0); 0x00 would be a state-assisted (NKpsk0) sign-in */
        const val PROLOGUE: Byte = 0x01
        const val P256_POINT = 65
        const val TAG = 16

        fun newEphemeral(): KeyPair =
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        /** A key pair from a private scalar and its public point (65 bytes, uncompressed); for tests. */
        fun keyPair(privateScalar: ByteArray, public65: ByteArray): KeyPair {
            val kf = KeyFactory.getInstance("EC")
            val priv = kf.generatePrivate(ECPrivateKeySpec(BigInteger(1, privateScalar), p256))
            return KeyPair(publicKey(public65), priv)
        }

        /** 33-byte compressed P-256 point (prefix 0x02 even Y, 0x03 odd Y) -> 65-byte uncompressed. */
        fun decompress(compressed: ByteArray): ByteArray {
            require(compressed.size == 33) { "expected 33-byte compressed point, got ${compressed.size}" }
            val prefix = compressed[0].toInt() and 0xFF
            require(prefix == 0x02 || prefix == 0x03) { "unexpected point prefix 0x%02x".format(prefix) }
            val p = (p256.curve.field as ECFieldFp).p
            val x = BigInteger(1, compressed.copyOfRange(1, 33))
            require(x < p) { "x out of range" }
            val rhs = (x.pow(3) + p256.curve.a * x + p256.curve.b).mod(p)
            var y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p) // p = 3 mod 4
            require(y.modPow(TWO, p) == rhs) { "not a point on P-256" }
            if (y.testBit(0) != (prefix == 0x03)) y = p.subtract(y)
            return byteArrayOf(0x04) + fixed(x.toByteArray()) + fixed(y.toByteArray())
        }

        /** Whether [point65] is an uncompressed point on P-256 (not the point at infinity). */
        fun isOnCurve(point65: ByteArray): Boolean {
            if (point65.size != 65 || point65[0].toInt() != 0x04) return false
            val p = (p256.curve.field as ECFieldFp).p
            val x = BigInteger(1, point65.copyOfRange(1, 33))
            val y = BigInteger(1, point65.copyOfRange(33, 65))
            if (x >= p || y >= p) return false
            return y.modPow(TWO, p) == (x.pow(3) + p256.curve.a * x + p256.curve.b).mod(p)
        }

        fun uncompressed(pub: ECPublicKey): ByteArray =
            byteArrayOf(0x04) + fixed(pub.w.affineX.toByteArray()) + fixed(pub.w.affineY.toByteArray())

        internal fun ecdh(priv: ECPrivateKey, peer65: ByteArray): ByteArray =
            KeyAgreement.getInstance("ECDH").apply { init(priv); doPhase(publicKey(peer65), true) }.generateSecret()

        internal fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, input: ByteArray, aad: ByteArray? = null): ByteArray =
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                if (aad != null) updateAAD(aad)
                doFinal(input)
            }

        private fun hkdf(ikm: ByteArray, salt: ByteArray, len: Int) = HybridTransport.hkdf(ikm, salt, ByteArray(0), len)

        private val p256: ECParameterSpec by lazy {
            AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
        }

        private fun publicKey(point65: ByteArray): ECPublicKey {
            require(isOnCurve(point65)) { "not an uncompressed P-256 point" }
            val w = ECPoint(BigInteger(1, point65.copyOfRange(1, 33)), BigInteger(1, point65.copyOfRange(33, 65)))
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(w, p256)) as ECPublicKey
        }

        /** Big-endian integer bytes (as BigInteger.toByteArray gives them) -> exactly 32 bytes. */
        private fun fixed(v: ByteArray): ByteArray = when {
            v.size == 32 -> v
            v.size > 32 -> v.copyOfRange(v.size - 32, v.size)
            else -> ByteArray(32 - v.size) + v
        }

        internal fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Transport encryption after the handshake (docs/PROTOCOL.md, sections 10 and
 * 11): every record is padded to a multiple of 32 bytes (zeros, then one byte
 * with the number of zeros) and sealed with AES-256-GCM, no associated data,
 * nonce = 8 zero bytes || 32-bit big-endian counter, one counter per direction.
 */
class NoiseCrypter(private val receiveKey: ByteArray, private val sendKey: ByteArray) {
    private var sendCounter = 0L
    private var receiveCounter = 0L

    fun encrypt(plaintext: ByteArray): ByteArray {
        val size = (plaintext.size + 1 + PADDING - 1) / PADDING * PADDING
        val padded = plaintext.copyOf(size).also { it[size - 1] = (size - plaintext.size - 1).toByte() }
        return NoiseHandshake.gcm(Cipher.ENCRYPT_MODE, sendKey, nonce(sendCounter++), padded)
    }

    /** Decrypts and unpads one record; throws if it does not authenticate or the padding is invalid. */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        val padded = NoiseHandshake.gcm(Cipher.DECRYPT_MODE, receiveKey, nonce(receiveCounter++), ciphertext)
        if (padded.isEmpty()) throw IllegalStateException("empty transport record")
        val zeros = padded[padded.size - 1].toInt() and 0xFF
        if (zeros + 1 > padded.size) throw IllegalStateException("invalid transport padding")
        return padded.copyOfRange(0, padded.size - zeros - 1)
    }

    private fun nonce(counter: Long): ByteArray {
        check(counter <= MAX_SEQUENCE) { "transport counter exhausted" }
        return ByteArray(12).also {
            it[8] = (counter ushr 24).toByte(); it[9] = (counter ushr 16).toByte()
            it[10] = (counter ushr 8).toByte(); it[11] = counter.toByte()
        }
    }

    companion object {
        const val PADDING = 32
        const val MAX_SEQUENCE = (1L shl 24) - 1
        const val POST_HANDSHAKE_PADDING = 512

        /**
         * The extra padding of the post-handshake message (EncodePaddedCBORMap):
         * CBOR || zeros || uint16-le(number of zeros), a multiple of 512 bytes.
         */
        fun padPostHandshake(cbor: ByteArray): ByteArray {
            val size = (cbor.size + 2 + POST_HANDSHAKE_PADDING - 1) / POST_HANDSHAKE_PADDING * POST_HANDSHAKE_PADDING
            val zeros = size - cbor.size - 2
            return cbor.copyOf(size).also {
                it[size - 2] = zeros.toByte()
                it[size - 1] = (zeros ushr 8).toByte()
            }
        }
    }
}

/** 2. (BigInteger.TWO only exists from Android 13 on; the app runs from Android 9.) */
private val TWO: BigInteger = BigInteger.valueOf(2)
