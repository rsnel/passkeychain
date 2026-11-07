package it.snel.passkeychain.hybrid

import it.snel.passkeychain.util.Dbg
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import it.snel.passkeychain.webauthn.Cbor

/**
 * caBLE v2 tunnel client: WebSocket + Noise KNpsk0 responder, as in Chromium
 * device/fido/cable/noise.cc and v2_handshake.cc for QR-initiated sign-ins
 * (see docs/PROTOCOL.md, section 6):
 *
 *   h = ck = "Noise_KNpsk0_P256_AESGCM_SHA256" padded with one zero byte
 *   MixHash([0x01])          // prologue of the QR flow
 *   MixHash(peerIdentity65)  // the browser's static key from the QR, uncompressed
 *   MixKeyAndHash(psk)
 *   -> e                     msg1 from the browser
 *   <- e, ee, se             msg2 from us
 *
 * With Debug logging on, h, ck, k and the raw messages are logged.
 *
 * [onHandshakeDone] is called once the handshake has completed (progress
 * display, and the Bluetooth advert can stop: the browser has found us).
 */
class NoiseTunnelClient(private val onHandshakeDone: () -> Unit = {}) : HybridTransport.TunnelClient {

    private val TAG = "NoiseTunnelClient"
    private val PROTOCOL_NAME = "Noise_KNpsk0_P256_AESGCM_SHA256"

    override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel {
        Dbg.d(TAG, "Connecting to $tunnelUrl")
        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .build()

        val incoming = LinkedBlockingQueue<ByteArray>()
        val ready = LinkedBlockingQueue<Boolean>()
        val headersRef = java.util.concurrent.atomic.AtomicReference<okhttp3.Headers>()

        val ws = client.newWebSocket(
            Request.Builder()
                .url(tunnelUrl)
                .header("Sec-WebSocket-Protocol", "fido.cable")
                .build(),
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    Dbg.d(TAG, "WebSocket open, headers:")
                    response.headers.forEach { (n, v) -> Dbg.d(TAG, "  $n: $v") }
                    headersRef.set(response.headers)
                    ready.offer(true)
                }
                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                    val arr = bytes.toByteArray()
                    Dbg.d(TAG, "WS recv ${arr.size} bytes: ${hex(arr)}")
                    incoming.offer(arr)
                }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    Dbg.e(TAG, "WebSocket failure: ${t.message}", t)
                    response?.headers?.forEach { (n, v) -> Dbg.e(TAG, "  resp $n: $v") }
                    ready.offer(false)
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    Dbg.d(TAG, "WS closed: $code $reason")
                }
            }
        )

        val opened = ready.poll(15, TimeUnit.SECONDS) ?: false
        if (!opened) throw HybridTransport.DeviceStageMissing("WebSocket did not open")

        val headers = headersRef.get() ?: throw HybridTransport.DeviceStageMissing("no response headers")
        val shardHeader = headers["X-Cable-Routing-Id"]
            ?: headers["X-caBLE-Shard"]
            ?: throw HybridTransport.DeviceStageMissing("routing header missing")
        Dbg.d(TAG, "routing header = $shardHeader")
        val routingId = hexToBytes(shardHeader.replace("-", ""))
        require(routingId.size == 3) { "routing ID must be 3 bytes, got ${routingId.size}" }

        // The PSK depends on the advert, which needs this routing ID first,
        // so the Noise channel is opened later, by HybridTransport.
        return object : HybridTransport.TunnelClient.NewTunnel {
            override val routingId: ByteArray = routingId
            override fun open(peerIdentity65: ByteArray, psk: ByteArray): HybridTransport.TunnelClient.Channel =
                NoiseResponderChannel(ws, incoming, NoiseState(peerIdentity65, psk))
        }
    }

    private fun hexToBytes(s: String): ByteArray {
        require(s.length % 2 == 0)
        return ByteArray(s.length / 2) { i ->
            ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
        }
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /**
     * Noise state, mirroring device/fido/cable/noise.cc.
     */
    private inner class NoiseState(
        val peerIdentity65: ByteArray,
        private val psk: ByteArray,
    ) {
        var h = ByteArray(32)
            private set
        var ck = ByteArray(32)
            private set
        var k = ByteArray(32)
            private set
        var nonce = 0L
            private set

        init {
            Dbg.d(TAG, "NoiseState init: psk           = ${hex(psk)}")
            Dbg.d(TAG, "NoiseState init: peerIdentity65 = ${hex(peerIdentity65)}")

            // Init(kKNpsk0): the 31-byte protocol name padded to 32 bytes; h = ck
            val nameBytes = PROTOCOL_NAME.toByteArray(Charsets.US_ASCII)
            ck = ByteArray(32)
            System.arraycopy(nameBytes, 0, ck, 0, minOf(nameBytes.size, 32))
            h = ck.copyOf()
            Dbg.d(TAG, "init ck = ${hex(ck)}")
            Dbg.d(TAG, "init h  = ${hex(h)}")

            // prologue: 0x01 for the QR flow (KNpsk0); 0x00 would be NKpsk0, for
            // state-assisted (linked) sign-ins, which this app does not do
            mixHash(byteArrayOf(0x01))
            Dbg.d(TAG, "after MixHash([0x01]) h = ${hex(h)}")

            // MixHash(peerIdentity65)
            mixHash(peerIdentity65)
            Dbg.d(TAG, "after MixHash(peer) h = ${hex(h)}")

            // MixKeyAndHash(psk)
            mixKeyAndHash(psk)
            Dbg.d(TAG, "after MixKeyAndHash(psk) ck = ${hex(ck)}")
            Dbg.d(TAG, "after MixKeyAndHash(psk) h  = ${hex(h)}")
            Dbg.d(TAG, "after MixKeyAndHash(psk) k  = ${hex(k)}")
        }

        fun mixHash(data: ByteArray) {
            h = sha256(h + data)
        }

        fun mixKey(ikm: ByteArray) {
            val out = hkdf2(ck, ikm)
            ck = out.first
            k = out.second
            nonce = 0
        }

        fun mixKeyAndHash(ikm: ByteArray) {
            val out = hkdf96(ikm, ck)
            ck = out.copyOfRange(0, 32)
            val hash = out.copyOfRange(32, 64)
            k = out.copyOfRange(64, 96)
            mixHash(hash)
            nonce = 0
        }

        fun encryptAndHash(plaintext: ByteArray): ByteArray {
            val nonceBytes = ByteArray(12)
            // counter big-endian in bytes 0-3; in this handshake it is always 0,
            // because every key is used for one AEAD operation only
            nonceBytes[0] = ((nonce ushr 24) and 0xFF).toByte()
            nonceBytes[1] = ((nonce ushr 16) and 0xFF).toByte()
            nonceBytes[2] = ((nonce ushr 8) and 0xFF).toByte()
            nonceBytes[3] = (nonce and 0xFF).toByte()
            nonce++
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonceBytes))
            c.updateAAD(h)
            val ct = c.doFinal(plaintext)
            mixHash(ct)
            return ct
        }

        fun decryptAndHash(ciphertext: ByteArray): ByteArray {
            val nonceBytes = ByteArray(12)
            nonceBytes[0] = ((nonce ushr 24) and 0xFF).toByte()
            nonceBytes[1] = ((nonce ushr 16) and 0xFF).toByte()
            nonceBytes[2] = ((nonce ushr 8) and 0xFF).toByte()
            nonceBytes[3] = (nonce and 0xFF).toByte()
            nonce++
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonceBytes))
            c.updateAAD(h)
            val pt = c.doFinal(ciphertext)
            mixHash(ciphertext)
            return pt
        }

        fun split(): Pair<ByteArray, ByteArray> = hkdf2(ck, ByteArray(0))
    }

    /**
     * Responder channel. On first receive(), reads msg1 (81 bytes: e_pub 65 + tag 16),
     * processes it, sends msg2 (81 bytes: e_pub 65 + tag 16), then splits and enters
     * transport mode. Subsequent receive()/send() use transport keys.
     */
    private inner class NoiseResponderChannel(
        private val ws: WebSocket,
        private val incoming: LinkedBlockingQueue<ByteArray>,
        private val noise: NoiseState,
    ) : HybridTransport.TunnelClient.Channel {

        private var txKey: ByteArray? = null
        private var rxKey: ByteArray? = null
        private var txNonce = 0L
        private var rxNonce = 0L
        private var handshakeDone = false

        override fun receive(): ByteArray {
            if (!handshakeDone) {
                Dbg.d(TAG, "receive(): handshake not done, running handshake")
                handshake()
                handshakeDone = true
                onHandshakeDone()
            }
            while (true) {
                Dbg.d(TAG, "receive(): waiting up to 120s for transport ciphertext from Chrome")
                val ciphertext = incoming.poll(120, TimeUnit.SECONDS)
                    ?: run {
                        Dbg.w(TAG, "receive(): timeout, no transport ciphertext from Chrome after post-handshake")
                        throw HybridTransport.DeviceStageMissing("timeout waiting for transport ciphertext")
                    }
                Dbg.d(TAG, "receive(): got transport ciphertext ${ciphertext.size} bytes: ${hex(ciphertext)}")
                val pt = decryptTransport(ciphertext)
                Dbg.d(TAG, "receive(): decrypted ${pt.size} bytes: ${hex(pt)}")
                if (pt.isEmpty()) {
                    Dbg.w(TAG, "receive(): empty plaintext, continuing")
                    continue
                }
                val first = pt[0].toInt() and 0xFF
                val second = if (pt.size >= 2) pt[1].toInt() and 0xFF else -1
                val secondIsCborMap = second in 0xA0..0xBF
                Dbg.d(TAG, "receive(): first=0x%02x second=0x%02x cborMap=%b size=${pt.size}".format(first, second and 0xFF, secondIsCborMap))

                // kShutdown: 1-byte message 0x02 (MessageType::kShutdown)
                if (pt.size == 1 && first == 0x02) {
                    Dbg.w(TAG, "receive(): kShutdown from Chrome")
                    throw HybridTransport.DeviceStageMissing("Chrome requested shutdown")
                }
                // kUpdate: 1-byte message 0x03
                if (pt.size == 1 && first == 0x03) {
                    Dbg.d(TAG, "receive(): kUpdate, ignoring")
                    continue
                }
                // authenticatorGetInfo has no parameters: a bare 0x04
                if (pt.size == 1 && first == CtapAuthenticator.CMD_GET_INFO) {
                    Dbg.d(TAG, "receive(): bare CTAP2 getInfo")
                    return pt
                }
                // MessageType::kCTAP (0x00) prefix, followed by a CTAP2 command byte
                if (first == 0x00 && pt.size >= 2 && second in 0x01..0x04) {
                    Dbg.d(TAG, "receive(): MessageType=kCTAP prefix, CTAP2 cmd=0x%02x".format(second))
                    return pt.copyOfRange(1, pt.size)
                }
                // Bare CTAP2 command: first byte is 0x01/0x02/0x04 followed by CBOR map.
                // Chrome in some configurations sends CTAP2 requests without the
                // MessageType prefix (observed for kAuthenticatorGetAssertion).
                if (first in 0x01..0x04 && secondIsCborMap) {
                    Dbg.d(TAG, "receive(): bare CTAP2 cmd=0x%02x (no MessageType prefix)".format(first))
                    return pt
                }
                // kJSON prefix with non-CBOR payload: ignore
                if (first == 0x01) {
                    Dbg.d(TAG, "receive(): kJSON prefix, ignoring")
                    continue
                }
                Dbg.w(TAG, "receive(): unrecognized message (first=0x%02x size=${pt.size}), discarding".format(first))
                continue
            }
        }

        override fun send(plaintext: ByteArray) {
            if (!handshakeDone) throw IllegalStateException("handshake not done")
            // The plaintext already starts with the CTAP2 status byte
            // (0x00 = CTAP2_OK). Chrome expects [status][CBOR] with no
            // MessageType prefix on outgoing responses: adding one produced
            // 'Trailing data bytes are not allowed' from Chrome's CTAP2 parser.
            val ct = encryptTransport(plaintext)
            Dbg.d(TAG, "transport send ${ct.size} bytes (plaintext ${plaintext.size}): ${hex(ct)}")
            ws.send(okio.ByteString.of(*ct))
        }

        override fun close() {
            ws.close(1000, "done")
        }

        private fun handshake() {
            val msg1 = incoming.poll(120, TimeUnit.SECONDS)
                ?: throw HybridTransport.DeviceStageMissing("timeout waiting for msg1")
            Dbg.d(TAG, "msg1 ${msg1.size} bytes: ${hex(msg1)}")
            require(msg1.size >= 65 + 16) { "msg1 too short: ${msg1.size}" }

            val ePubI = msg1.copyOfRange(0, 65)
            val tag1 = msg1.copyOfRange(65, msg1.size)
            Dbg.d(TAG, "msg1 e_pub_i = ${hex(ePubI)}")
            Dbg.d(TAG, "msg1 tag1 = ${hex(tag1)}")
            if (!isOnCurve(ePubI)) throw IllegalStateException("The computer sent an invalid key")

            // Responder generates its ephemeral
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val ephR = kpg.generateKeyPair()
            val ephPubR = uncompressed(ephR.public as ECPublicKey)
            Dbg.d(TAG, "responder e_pub_r = ${hex(ephPubR)}")

            // msg1 (-> e): the e token, then its (empty) payload. In a psk
            // handshake every e token is MixHash(e) and MixKey(e) (Noise spec,
            // section 9). The ee DH belongs to msg2: it must not change k
            // before tag1 is checked.
            noise.mixHash(ePubI)
            Dbg.d(TAG, "after MixHash(e_pub_i) h = ${hex(noise.h)}")
            noise.mixKey(ePubI)
            Dbg.d(TAG, "after MixKey(e_pub_i) ck = ${hex(noise.ck)}")
            Dbg.d(TAG, "after MixKey(e_pub_i) k  = ${hex(noise.k)}")

            val pt1 = noise.decryptAndHash(tag1)
            Dbg.d(TAG, "msg1 plaintext = ${hex(pt1)} (expected empty)")

            // msg2 (<- e, ee, se):
            //   MixHash(e_pub_r); MixKey(e_pub_r)   e token (psk handshake)
            //   MixKey(ECDH(e_r, e_i))              ee
            //   MixKey(ECDH(e_r, s_i))              se, s_i = the QR key
            //   EncryptAndHash(empty)               payload
            noise.mixHash(ephPubR)
            Dbg.d(TAG, "after MixHash(e_pub_r) h = ${hex(noise.h)}")
            noise.mixKey(ephPubR)
            Dbg.d(TAG, "after MixKey(e_pub_r) ck = ${hex(noise.ck)}")
            Dbg.d(TAG, "after MixKey(e_pub_r) k  = ${hex(noise.k)}")

            val ee = ecdh(ephR.private as ECPrivateKey, ePubI)
            Dbg.d(TAG, "ee = ${hex(ee)}")

            // Offline verification: capture the exact inputs to MixKey(ee).
            // msg2_check.py computes HKDF2(ck_before_ee, ee) and should produce
            // exactly the ck/k logged immediately after.
            val ckBeforeEe = noise.ck.copyOf()
            Dbg.d(TAG, "msg2-check ck_before_ee = ${hex(ckBeforeEe)}")
            Dbg.d(TAG, "msg2-check ephPubR     = ${hex(ephPubR)}")
            Dbg.d(TAG, "msg2-check ee          = ${hex(ee)}")

            noise.mixKey(ee)
            Dbg.d(TAG, "after MixKey(ee) ck = ${hex(noise.ck)}")
            Dbg.d(TAG, "after MixKey(ee) k  = ${hex(noise.k)}")
            Dbg.d(TAG, "after MixKey(ee) h  = ${hex(noise.h)}")

            // se: our ephemeral with the browser's static key from the QR
            val ckBeforeSe = noise.ck.copyOf()
            val se = ecdh(ephR.private as ECPrivateKey, noise.peerIdentity65)
            Dbg.d(TAG, "msg2-check ck_before_se = ${hex(ckBeforeSe)}")
            Dbg.d(TAG, "msg2-check se          = ${hex(se)}")
            noise.mixKey(se)
            Dbg.d(TAG, "after MixKey(se) ck = ${hex(noise.ck)}")
            Dbg.d(TAG, "after MixKey(se) k  = ${hex(noise.k)}")

            val tag2 = noise.encryptAndHash(ByteArray(0))
            val msg2 = ephPubR + tag2
            Dbg.d(TAG, "msg2 ${msg2.size} bytes: ${hex(msg2)}")
            ws.send(okio.ByteString.of(*msg2))

            // Noise Split: the first key encrypts initiator -> responder (we
            // receive with it), the second responder -> initiator (we send).
            val (readKey, writeKey) = noise.split()
            txKey = writeKey
            rxKey = readKey
            Dbg.d(TAG, "split readKey  = ${hex(readKey)}")
            Dbg.d(TAG, "split writeKey = ${hex(writeKey)}")

            // Per Chromium's v2_authenticator.cc OnTunnelData: after the handshake
            // response (msg2), the authenticator sends a post-handshake message
            // with its features and a CTAP2 getInfo response. Chrome will not
            // send the actual CTAP2 command until it sees this.
            val getInfo = CtapAuthenticator.getInfo()
            val postHandshakeCbor = Cbor.encode(linkedMapOf<Any, Any>(
                1 to getInfo,                             // getInfo, CBOR byte string
                3 to listOf("ctap")                       // features
            ))
            Dbg.d(TAG, "post-handshake CBOR ${postHandshakeCbor.size} bytes: ${hex(postHandshakeCbor)}")

            // Chromium's v2_authenticator.cc sends the post-handshake message
            // through EncodePaddedCBORMap before encrypting it. The padded
            // format is: CBOR || zero bytes || uint16-le(num_padding), with
            // the total padded size a multiple of kPostHandshakeMsgPaddingGranularity (512).
            val granularity = 512
            val totalUnpadded = postHandshakeCbor.size + 2  // +2 for the uint16 length
            val paddedSize = ((totalUnpadded + granularity - 1) / granularity) * granularity
            val numPadding = paddedSize - postHandshakeCbor.size - 2
            val postHandshake = ByteArray(paddedSize)
            System.arraycopy(postHandshakeCbor, 0, postHandshake, 0, postHandshakeCbor.size)
            // numPadding as uint16 little-endian at the last two bytes
            postHandshake[paddedSize - 2] = (numPadding and 0xFF).toByte()
            postHandshake[paddedSize - 1] = ((numPadding ushr 8) and 0xFF).toByte()
            Dbg.d(TAG, "post-handshake padded ${postHandshake.size} bytes (padding=$numPadding): ${hex(postHandshake)}")
            val postHandshakeCt = encryptTransport(postHandshake)
            Dbg.d(TAG, "post-handshake ciphertext ${postHandshakeCt.size} bytes: ${hex(postHandshakeCt)}")
            ws.send(okio.ByteString.of(*postHandshakeCt))
            Dbg.d(TAG, "post-handshake sent; waiting for CTAP2 request")
        }

        private fun encryptTransport(plaintext: ByteArray): ByteArray {
            val key = txKey ?: throw IllegalStateException("no tx key")
            // Crypter-style padding (from v2_handshake.cc Crypter::Encrypt):
            // pad to a multiple of 32, last byte = number of zero bytes added.
            val granularity = 32
            val paddedSize = ((plaintext.size + 1 + granularity - 1) / granularity) * granularity
            val numZeros = paddedSize - plaintext.size - 1
            val padded = ByteArray(paddedSize)
            System.arraycopy(plaintext, 0, padded, 0, plaintext.size)
            // bytes [plaintext.size .. paddedSize-2] are already zero
            padded[paddedSize - 1] = numZeros.toByte()
            Dbg.d(TAG, "encryptTransport: plaintext ${plaintext.size} -> padded ${paddedSize} (numZeros=$numZeros)")
            // Chromium's ConstructNonce (v2_handshake.cc): 12-byte nonce,
            // first 8 bytes zero, last 4 bytes big-endian counter.
            val nonceBytes = ByteArray(12)
            nonceBytes[8] = ((txNonce ushr 24) and 0xFF).toByte()
            nonceBytes[9] = ((txNonce ushr 16) and 0xFF).toByte()
            nonceBytes[10] = ((txNonce ushr 8) and 0xFF).toByte()
            nonceBytes[11] = (txNonce and 0xFF).toByte()
            txNonce++
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceBytes))
            return c.doFinal(padded)
        }

        private fun decryptTransport(ciphertext: ByteArray): ByteArray {
            val key = rxKey ?: throw IllegalStateException("no rx key")
            // Chromium's ConstructNonce: last 4 bytes big-endian counter.
            val nonceBytes = ByteArray(12)
            nonceBytes[8] = ((rxNonce ushr 24) and 0xFF).toByte()
            nonceBytes[9] = ((rxNonce ushr 16) and 0xFF).toByte()
            nonceBytes[10] = ((rxNonce ushr 8) and 0xFF).toByte()
            nonceBytes[11] = (rxNonce and 0xFF).toByte()
            rxNonce++
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceBytes))
            val padded = c.doFinal(ciphertext)
            if (padded.isEmpty()) throw IllegalStateException("empty padded plaintext")
            val paddingLength = padded[padded.size - 1].toInt() and 0xFF
            if (paddingLength + 1 > padded.size) throw IllegalStateException("invalid Crypter padding length $paddingLength")
            val plaintext = padded.copyOfRange(0, padded.size - paddingLength - 1)
            Dbg.d(TAG, "decryptTransport: padded ${padded.size} -> plaintext ${plaintext.size} (paddingLength=$paddingLength)")
            return plaintext
        }
    }

    companion object {
        /**
         * Decompress a 33-byte compressed P-256 point (prefix 0x02 or 0x03)
         * into a 65-byte uncompressed X9.62 point (0x04 || X || Y).
         * Needed because the Noise handshake's peer identity is the 65-byte
         * form, while the QR carries the 33-byte compressed form.
         */
        fun decompressPeerIdentity(compressed: ByteArray): ByteArray {
            require(compressed.size == 33) { "expected 33-byte compressed point, got ${compressed.size}" }
            val prefix = compressed[0].toInt() and 0xFF
            require(prefix == 0x02 || prefix == 0x03) { "unexpected point prefix 0x%02x".format(prefix) }
            val params = p256Params()
            val p = (params.curve.field as java.security.spec.ECFieldFp).p
            val a = params.curve.a
            val b = params.curve.b
            val x = java.math.BigInteger(1, compressed.copyOfRange(1, 33))
            val rhs = (x.modPow(java.math.BigInteger.TWO, p) * x + a * x + b).mod(p)
            val exp = p.add(java.math.BigInteger.ONE).divide(java.math.BigInteger.valueOf(4))
            var y = rhs.modPow(exp, p)
            // prefix 0x02 = even Y, 0x03 = odd Y
            if (y.testBit(0)) {
                if (prefix == 0x02) y = p.subtract(y)
            } else {
                if (prefix == 0x03) y = p.subtract(y)
            }
            val xb = fixed(x.toByteArray(), 32)
            val yb = fixed(y.toByteArray(), 32)
            return byteArrayOf(0x04) + xb + yb
        }

        private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

        private fun hkdf2(ck: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
            val out = hkdf(ikm, ck, ByteArray(0), 64)
            return out.copyOfRange(0, 32) to out.copyOfRange(32, 64)
        }

        private fun hkdf96(ikm: ByteArray, salt: ByteArray): ByteArray = hkdf(ikm, salt, ByteArray(0), 96)

        private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            val out = ByteArray(len)
            var t = ByteArray(0); var pos = 0; var counter = 1
            while (pos < len) {
                mac.reset(); mac.update(t); mac.update(info); mac.update(counter.toByte())
                t = mac.doFinal()
                val n = minOf(t.size, len - pos)
                System.arraycopy(t, 0, out, pos, n); pos += n; counter++
            }
            return out
        }

        private fun p256Params(): ECParameterSpec =
            AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)

        private fun uncompressed(pub: ECPublicKey): ByteArray {
            val x = fixed(pub.w.affineX.toByteArray(), 32)
            val y = fixed(pub.w.affineY.toByteArray(), 32)
            return byteArrayOf(0x04) + x + y
        }

        private fun fixed(v: ByteArray, len: Int): ByteArray {
            if (v.size == len) return v
            val r = ByteArray(len)
            if (v.size > len) System.arraycopy(v, v.size - len, r, 0, len)
            else System.arraycopy(v, 0, r, len - v.size, v.size)
            return r
        }

        /**
         * Return true if the 65-byte uncompressed point is on the P-256 curve.
         * If ePubI is not on the curve, MixHash(e_pub_i) will diverge from
         * Chrome's and tag1 will fail AEAD authentication.
         */
        fun isOnCurve(point65: ByteArray): Boolean {
            if (point65.size != 65 || point65[0].toInt() != 0x04) return false
            val params = p256Params()
            val p = (params.curve.field as java.security.spec.ECFieldFp).p
            val a = params.curve.a
            val b = params.curve.b
            val x = java.math.BigInteger(1, point65.copyOfRange(1, 33))
            val y = java.math.BigInteger(1, point65.copyOfRange(33, 65))
            if (x >= p || y >= p) return false
            val lhs = y.modPow(java.math.BigInteger.TWO, p).mod(p)
            val rhs = (x.modPow(java.math.BigInteger.valueOf(3), p) + a.multiply(x) + b).mod(p)
            return lhs == rhs
        }

        private fun ecdh(priv: ECPrivateKey, peer65: ByteArray): ByteArray {
            require(peer65.size == 65 && peer65[0].toInt() == 0x04) { "expected uncompressed point" }
            val x = BigInteger(1, peer65.copyOfRange(1, 33))
            val y = BigInteger(1, peer65.copyOfRange(33, 65))
            val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Params()))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(priv)
            ka.doPhase(pub, true)
            return ka.generateSecret()
        }

        private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    }
}
