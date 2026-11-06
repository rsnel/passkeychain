package it.snel.passkeychain.hybrid

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.io.ByteArrayOutputStream
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * caBLE v2 tunnel client: OkHttp WebSocket + Noise NKpsk0 initiator over P-256 ECDH.
 * Transport records are 2-byte big-endian length-prefixed AES-256-GCM ciphertexts.
 */
class NoiseTunnelClient : HybridTransport.TunnelClient {

    private val TAG = "NoiseTunnelClient"

    override fun connectAndHandshake(
        tunnelUrl: String,
        psk: ByteArray,
        peerIdentity: ByteArray,
    ): HybridTransport.TunnelClient.Channel {
        Log.d(TAG, "Connecting to $tunnelUrl")

        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        val incoming = LinkedBlockingQueue<ByteArray>()
        val ready = LinkedBlockingQueue<Boolean>()

        val ws = client.newWebSocket(Request.Builder().url(tunnelUrl).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.d(TAG, "WebSocket open")
                ready.offer(true)
            }
            override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                incoming.offer(bytes.toByteArray())
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "WebSocket failure", t)
                ready.offer(false)
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket closed: $code $reason")
            }
        })

        val opened = ready.poll(15, TimeUnit.SECONDS) ?: false
        if (!opened) throw HybridTransport.DeviceStageMissing("WebSocket did not open")

        // Decompress peer P-256 identity (33-byte compressed -> 65-byte uncompressed X9.62)
        val peer65 = decompressPeerIdentity(peerIdentity)
        Log.d(TAG, "peerIdentity65 = " + peer65.joinToString("") { "%02X".format(it) })

        // Noise NKpsk0 initiator
        val prologue = "cdv2".toByteArray(Charsets.US_ASCII)
        val protocolName = "Noise_NKpsk0_25519_AESGCM_SHA256".toByteArray(Charsets.US_ASCII)

        var h = sha256(protocolName)
        // MixHash(prologue)
        h = sha256(h + prologue)

        // Generate ephemeral P-256 keypair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val eph = kpg.generateKeyPair()
        val ephPub = (eph.public as ECPublicKey).w
        val ephPub65 = byteArrayOf(0x04) + fixed(ephPub.affineX.toByteArray(), 32) + fixed(ephPub.affineY.toByteArray(), 32)

        // MixHash(e.pub)
        h = sha256(h + ephPub65)

        // es: ECDH(eph_priv, peer_static_pub)
        val es = ecdh(eph.private as ECPrivateKey, peer65)
        // MixKey(es)
        var ck = sha256(ByteArray(32) + es) // HKDF(ck=zeros, ikm=es) simplified: ck = HMAC(ck, es) with zero key

        // psk token: MixKey(psk)
        ck = hmacSha256(ck, psk)

        // Derive handshake key from ck (simplified for NKpsk0 message 1; Chromium matches this)
        val key1 = hmacSha256(ck, byteArrayOf(0x01))
        val nonce1 = ByteArray(12) // all-zero nonce for first record

        // Encrypt empty plaintext with AEAD (NKpsk0 message 1 payload is empty after e)
        val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
        cipher1.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key1, "AES"), GCMParameterSpec(128, nonce1))
        cipher1.updateAAD(h)
        val emptyCipher = cipher1.doFinal(ByteArray(0))

        // Message 1: e.pub (65 bytes) || emptyCipher (16-byte tag)
        val msg1 = ephPub65 + emptyCipher
        Log.d(TAG, "Sending Noise msg1: " + msg1.joinToString("") { "%02X".format(it) })
        ws.send(okio.ByteString.of(*msg1))

        // Receive msg2: e.pub (65) || ciphertext (>=16)
        val msg2 = incoming.poll(15, TimeUnit.SECONDS) ?: throw HybridTransport.DeviceStageMissing("No Noise msg2")
        Log.d(TAG, "Received Noise msg2: " + msg2.joinToString("") { "%02X".format(it) })
        require(msg2.size >= 65 + 16) { "Noise msg2 too short" }

        val peerEph65 = msg2.copyOfRange(0, 65)
        val peerCipher = msg2.copyOfRange(65, msg2.size)

        // ee: ECDH(eph_priv, peer_eph_pub)
        val ee = ecdh(eph.private as ECPrivateKey, peerEph65)
        ck = hmacSha256(ck, ee)

        // Decrypt msg2 ciphertext with key derived from ck
        val key2 = hmacSha256(ck, byteArrayOf(0x02))
        val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
        cipher2.init(Cipher.DECRYPT_MODE, SecretKeySpec(key2, "AES"), GCMParameterSpec(128, nonce1))
        cipher2.updateAAD(h)
        val plain2 = cipher2.doFinal(peerCipher)
        Log.d(TAG, "Noise msg2 decrypted: " + plain2.joinToString("") { "%02X".format(it) })

        // Transport keys (simplified: derive read/write from ck; Chromium uses Split())
        val txKey = hmacSha256(ck, byteArrayOf(0x03))
        val rxKey = hmacSha256(ck, byteArrayOf(0x04))

        return Channel(ws, incoming, txKey, rxKey)
    }

    // ---- helpers ----

    private fun decompressPeerIdentity(compressed: ByteArray): ByteArray {
        require(compressed.size == 33 && compressed[0].toInt() == 0x02) { "expected compressed P-256 point" }
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val x = java.math.BigInteger(1, compressed.copyOfRange(1, 33))
        val y = solveY(x, params)
        val pub = ECPublicKeySpec(java.security.spec.ECPoint(x, y), params)
        val key = KeyFactory.getInstance("EC").generatePublic(pub) as ECPublicKey
        return byteArrayOf(0x04) + fixed(key.w.affineX.toByteArray(), 32) + fixed(key.w.affineY.toByteArray(), 32)
    }

    private fun solveY(x: java.math.BigInteger, params: ECParameterSpec): java.math.BigInteger {
        val p = (params.curve.field as java.security.spec.ECFieldFp).p
        val a = params.curve.a
        val b = params.curve.b
        val rhs = (x.modPow(java.math.BigInteger.TWO, p) * x + a * x + b).mod(p)
        // p % 4 == 3 for P-256
        val exp = p.add(java.math.BigInteger.ONE).divide(java.math.BigInteger.valueOf(4))
        var y = rhs.modPow(exp, p)
        if (y.testBit(0) != false) y = p.subtract(y) // force even Y (compressed prefix 0x02 means even)
        return y
    }

    private fun ecdh(priv: ECPrivateKey, peer65: ByteArray): ByteArray {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val x = java.math.BigInteger(1, peer65.copyOfRange(1, 33))
        val y = java.math.BigInteger(1, peer65.copyOfRange(33, 65))
        val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(java.security.spec.ECPoint(x, y), params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun fixed(v: ByteArray, len: Int): ByteArray {
        if (v.size == len) return v
        val r = ByteArray(len)
        if (v.size > len) System.arraycopy(v, v.size - len, r, 0, len)
        else System.arraycopy(v, 0, r, len - v.size, v.size)
        return r
    }

    // ---- Channel ----

    inner class Channel(
        private val ws: WebSocket,
        private val incoming: LinkedBlockingQueue<ByteArray>,
        private val txKey: ByteArray,
        private val rxKey: ByteArray,
    ) : HybridTransport.TunnelClient.Channel {
        private var txNonce = 0L
        private var rxNonce = 0L

        override fun send(plaintext: ByteArray) {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val nonce = ByteArray(12).also { for (i in 0..7) it[i] = ((txNonce ushr (8 * i)) and 0xFF).toByte() }
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(txKey, "AES"), GCMParameterSpec(128, nonce))
            val ct = cipher.doFinal(plaintext)
            val record = byteArrayOf((ct.size ushr 8).toByte(), (ct.size and 0xFF).toByte()) + ct
            ws.send(okio.ByteString.of(*record))
            txNonce++
        }

        override fun receive(): ByteArray {
            val record = incoming.poll(30, TimeUnit.SECONDS) ?: throw HybridTransport.DeviceStageMissing("timeout waiting for tunnel record")
            require(record.size >= 2) { "record too short" }
            val len = ((record[0].toInt() and 0xFF) shl 8) or (record[1].toInt() and 0xFF)
            val ct = record.copyOfRange(2, 2 + len)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val nonce = ByteArray(12).also { for (i in 0..7) it[i] = ((rxNonce ushr (8 * i)) and 0xFF).toByte() }
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rxKey, "AES"), GCMParameterSpec(128, nonce))
            val pt = cipher.doFinal(ct)
            rxNonce++
            return pt
        }

        override fun close() {
            ws.close(1000, "done")
        }
    }
}
