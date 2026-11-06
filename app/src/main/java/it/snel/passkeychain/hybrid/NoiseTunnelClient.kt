package it.snel.passkeychain.hybrid

import android.util.Log
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

/**
 * caBLE v2 tunnel client. WebSocket + Noise NKpsk0 responder, following
 * Chromium device/fido/cable/noise.cc exactly:
 *
 *   Init(kNKpsk0)          -> ck = zeros || "Noise_NKpsk0_P256_AESGCM_SHA256", h = ck
 *   MixHash([0x00])
 *   MixHash(peerIdentity65)  // the QR's 65-byte uncompressed P-256 public key
 *   MixKeyAndHash(psk)       // HKDF<96>(ikm=psk, salt=ck) -> (ck, hash, key); MixHash(hash)
 *
 * Then the NKpsk0 pattern: <- e, ee (msg2 from responder).
 *
 * Everything is logged: h, ck, k, nonce counter, and raw message bytes.
 */
class NoiseTunnelClient : HybridTransport.TunnelClient {

    private val TAG = "NoiseTunnelClient"
    private val PROTOCOL_NAME = "Noise_NKpsk0_P256_AESGCM_SHA256"

    override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel {
        Log.d(TAG, "Connecting to $tunnelUrl")
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
                    Log.d(TAG, "WebSocket open, headers:")
                    response.headers.forEach { (n, v) -> Log.d(TAG, "  $n: $v") }
                    headersRef.set(response.headers)
                    ready.offer(true)
                }
                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                    val arr = bytes.toByteArray()
                    Log.d(TAG, "WS recv ${arr.size} bytes: ${hex(arr)}")
                    incoming.offer(arr)
                }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    Log.e(TAG, "WebSocket failure: ${t.message}", t)
                    response?.headers?.forEach { (n, v) -> Log.e(TAG, "  resp $n: $v") }
                    ready.offer(false)
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    Log.d(TAG, "WS closed: $code $reason")
                }
            }
        )

        val opened = ready.poll(15, TimeUnit.SECONDS) ?: false
        if (!opened) throw HybridTransport.DeviceStageMissing("WebSocket did not open")

        val headers = headersRef.get() ?: throw HybridTransport.DeviceStageMissing("no response headers")
        val shardHeader = headers["X-Cable-Routing-Id"]
            ?: headers["X-caBLE-Shard"]
            ?: throw HybridTransport.DeviceStageMissing("routing header missing")
        Log.d(TAG, "routing header = $shardHeader")
        val routingId = hexToBytes(shardHeader.replace("-", ""))
        require(routingId.size == 3) { "routing ID must be 3 bytes, got ${routingId.size}" }

        // Construct the channel lazily. NoiseResponderChannel reads
        // STATIC_PSK and STATIC_EID_PLAINTEXT in its init; those statics are
        // set by HybridTransport.authenticate() after connectNewTunnel
        // returns. Constructing the channel here would freeze the zero
        // defaults. Lazy construction defers init until authenticate()
        // accesses newTunnel.channel, which is after the statics are set.
        return object : HybridTransport.TunnelClient.NewTunnel {
            override val routingId: ByteArray = routingId
            override val channel: HybridTransport.TunnelClient.Channel by lazy {
                NoiseResponderChannel(ws, incoming)
            }
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
        private val peerIdentity65: ByteArray,
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
            Log.d(TAG, "NoiseState init: psk           = ${hex(psk)}")
            Log.d(TAG, "NoiseState init: peerIdentity65 = ${hex(peerIdentity65)}")
            Log.d(TAG, "NoiseState init: eidPlaintext  = ${hex(STATIC_EID_PLAINTEXT)}")

            // Init(kNKpsk0): ck = zeros || protocol_name; h = ck
            val nameBytes = PROTOCOL_NAME.toByteArray(Charsets.US_ASCII)
            ck = ByteArray(32)
            System.arraycopy(nameBytes, 0, ck, 0, minOf(nameBytes.size, 32))
            h = ck.copyOf()
            Log.d(TAG, "init ck = ${hex(ck)}")
            Log.d(TAG, "init h  = ${hex(h)}")

            // NKpsk0 responder uses prologue = 0x00 (Chromium RespondToHandshake,
            // NKpsk0 branch uses 0x00.
            mixHash(byteArrayOf(0x00))
            Log.d(TAG, "after MixHash([0x01]) h = ${hex(h)}")

            // MixHash(peerIdentity65)
            mixHash(peerIdentity65)
            Log.d(TAG, "after MixHash(peer) h = ${hex(h)}")

            // MixKeyAndHash(psk)
            mixKeyAndHash(psk)
            Log.d(TAG, "after MixKeyAndHash(psk) ck = ${hex(ck)}")
            Log.d(TAG, "after MixKeyAndHash(psk) h  = ${hex(h)}")
            Log.d(TAG, "after MixKeyAndHash(psk) k  = ${hex(k)}")
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
            // first 4 bytes BE counter
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
    ) : HybridTransport.TunnelClient.Channel {

        private val noise: NoiseState
        private var txKey: ByteArray? = null
        private var rxKey: ByteArray? = null
        private var txNonce = 0L
        private var rxNonce = 0L
        private var handshakeDone = false

        init {
            // We do not yet know peerIdentity or psk from inside the channel.
            // Both are injected by HybridTransport via the NewTunnel interface
            // in a real implementation; for now we read them from static fields
            // that HybridTransport sets before calling receive().
            noise = NoiseState(STATIC_PEER_IDENTITY, STATIC_PSK)
        }

        override fun receive(): ByteArray {
            if (!handshakeDone) {
                handshake()
                handshakeDone = true
            }
            val record = incoming.poll(120, TimeUnit.SECONDS)
                ?: throw HybridTransport.DeviceStageMissing("timeout waiting for transport record")
            Log.d(TAG, "transport recv record ${record.size} bytes")
            // transport record: 2-byte BE length || ciphertext
            require(record.size >= 2) { "record too short" }
            val len = ((record[0].toInt() and 0xFF) shl 8) or (record[1].toInt() and 0xFF)
            val ct = record.copyOfRange(2, 2 + len)
            return decryptTransport(ct)
        }

        override fun send(plaintext: ByteArray) {
            if (!handshakeDone) throw IllegalStateException("handshake not done")
            val ct = encryptTransport(plaintext)
            val record = byteArrayOf((ct.size ushr 8).toByte(), (ct.size and 0xFF).toByte()) + ct
            Log.d(TAG, "transport send ${record.size} bytes: ${hex(record)}")
            ws.send(okio.ByteString.of(*record))
        }

        override fun close() {
            ws.close(1000, "done")
        }

        private fun handshake() {
            val msg1 = incoming.poll(120, TimeUnit.SECONDS)
                ?: throw HybridTransport.DeviceStageMissing("timeout waiting for msg1")
            Log.d(TAG, "msg1 ${msg1.size} bytes: ${hex(msg1)}")
            require(msg1.size >= 65 + 16) { "msg1 too short: ${msg1.size}" }

            val ePubI = msg1.copyOfRange(0, 65)
            val tag1 = msg1.copyOfRange(65, msg1.size)
            Log.d(TAG, "msg1 e_pub_i = ${hex(ePubI)}")
            Log.d(TAG, "msg1 tag1 = ${hex(tag1)}")
            Log.d(TAG, "msg1 e_pub_i on curve: ${isOnCurve(ePubI)}")

            // Responder generates its ephemeral
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val ephR = kpg.generateKeyPair()
            val ephPubR = uncompressed(ephR.public as ECPublicKey)
            Log.d(TAG, "responder e_pub_r = ${hex(ephPubR)}")

            // Process msg1 in the order the Noise pattern dictates:
            //   1. MixHash(e_pub_i)          (e token)
            //   2. DecryptAndHash(tag1)      (the payload after e)
            // The ee DH belongs to msg2, NOT msg1, so it must not touch k before
            // tag1 is authenticated. Getting this order wrong produces exactly
            // the AEAD open failure we saw: decrypting with a key that was
            // already advanced by MixKey(ee).
            noise.mixHash(ePubI)
            Log.d(TAG, "after MixHash(e_pub_i) h = ${hex(noise.h)}")

            // Chromium's RespondToHandshake does, for the NKpsk0 branch:
            //   noise.MixHash(peer_point_bytes);
            //   noise.MixKey(peer_point_bytes);
            //   // no es DH (identity is null)
            //   noise.DecryptAndHash(ciphertext);
            noise.mixKey(ePubI)
            Log.d(TAG, "after MixKey(e_pub_i) ck = ${hex(noise.ck)}")
            Log.d(TAG, "after MixKey(e_pub_i) k  = ${hex(noise.k)}")

            val pt1 = noise.decryptAndHash(tag1)
            Log.d(TAG, "msg1 plaintext = ${hex(pt1)} (expected empty)")

            // Build msg2: <- e, ee
            //   1. MixHash(e_pub_r)          (e token)
            //   2. ee = ECDH(eph_priv_r, e_pub_i); MixKey(ee)
            //   3. EncryptAndHash(empty)     (payload)
            noise.mixHash(ephPubR)
            Log.d(TAG, "after MixHash(e_pub_r) h = ${hex(noise.h)}")
            // Chromium's ProcessResponse does MixHash(e_pub_r), then
            // MixKey(e_pub_r), then MixKey(ee). The MixKey(e_pub_r) was
            // missing here, so the initiator's DecryptAndHash saw a different
            // key than we used to encrypt tag2 and rejected msg2 with
            // "Invalid caBLE handshake message".
            noise.mixKey(ephPubR)
            Log.d(TAG, "after MixKey(e_pub_r) ck = ${hex(noise.ck)}")
            Log.d(TAG, "after MixKey(e_pub_r) k  = ${hex(noise.k)}")

            val ee = ecdh(ephR.private as ECPrivateKey, ePubI)
            Log.d(TAG, "ee = ${hex(ee)}")
            noise.mixKey(ee)
            Log.d(TAG, "after MixKey(ee) ck = ${hex(noise.ck)}")
            Log.d(TAG, "after MixKey(ee) k  = ${hex(noise.k)}")
            Log.d(TAG, "after MixKey(ee) h  = ${hex(noise.h)}")

            val tag2 = noise.encryptAndHash(ByteArray(0))
            val msg2 = ephPubR + tag2
            Log.d(TAG, "msg2 ${msg2.size} bytes: ${hex(msg2)}")
            ws.send(okio.ByteString.of(*msg2))

            // Split
            val (t, r) = noise.split()
            txKey = t
            rxKey = r
            Log.d(TAG, "split txKey = ${hex(t)}")
            Log.d(TAG, "split rxKey = ${hex(r)}")
        }

        private fun encryptTransport(plaintext: ByteArray): ByteArray {
            val key = txKey ?: throw IllegalStateException("no tx key")
            val nonceBytes = ByteArray(12)
            for (i in 0..7) nonceBytes[i] = ((txNonce ushr (8 * i)) and 0xFF).toByte()
            txNonce++
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceBytes))
            return c.doFinal(plaintext)
        }

        private fun decryptTransport(ciphertext: ByteArray): ByteArray {
            val key = rxKey ?: throw IllegalStateException("no rx key")
            val nonceBytes = ByteArray(12)
            for (i in 0..7) nonceBytes[i] = ((rxNonce ushr (8 * i)) and 0xFF).toByte()
            rxNonce++
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceBytes))
            return c.doFinal(ciphertext)
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

        // Set by HybridTransport before calling receive(). Ugly but pragmatic for now.
        @Volatile var STATIC_PEER_IDENTITY: ByteArray = ByteArray(65)
        @Volatile var STATIC_PSK: ByteArray = ByteArray(32)
        // Diagnostic only: the 16-byte EID plaintext whose bytes are the salt
        // for the PSK derivation. Logged so we can cross-check HybridTransport
        // and NoiseState see the same bytes.
        @Volatile var STATIC_EID_PLAINTEXT: ByteArray = ByteArray(16)
        // Responder's static P-256 private key, PKCS#8 DER. Used for the es DH
        // in msg1. Its public half is what the QR carries as peerPublicKey.
        @Volatile var STATIC_RESPONDER_PRIV: ByteArray? = null

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
