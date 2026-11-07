package it.snel.passkeychain.hybrid

import java.util.UUID
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.webauthn.Assertion
import it.snel.passkeychain.webauthn.Cbor
import java.security.SecureRandom
import javax.crypto.Cipher
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class HybridTransport(
    private val ble: BleAdvertiser,
    private val tunnel: TunnelClient,
    /** Reports how far the exchange is, for the progress list on screen. */
    private val progress: (Progress) -> Unit = {},
) {
    sealed interface Progress {
        /** connecting to the tunnel server [host] */
        data class TunnelOpening(val host: String) : Progress
        /** the tunnel is open; the Bluetooth broadcast starts now */
        data object TunnelOpen : Progress
        /** broadcasting; now waiting for the browser to connect and start the Noise handshake */
        data object Broadcasting : Progress
    }

    class DeviceStageMissing(stage: String) :
        UnsupportedOperationException("hybrid stage '$stage' needs on-device BLE/network and is not wired in this build")

    interface BleAdvertiser {
        fun advertise(serviceUuid: UUID, payload: ByteArray)
        fun stop()
    }

    interface TunnelClient {
        /**
         * Connect to wss://<tunnelDomain>/cable/new/<hex(tunnelId)>, with the
         * fido.cable subprotocol, and return the routing ID read from the
         * X-caBLE-Shard response header. The WebSocket must remain open and
         * ready to send/receive Noise handshake bytes.
         */
        fun connectNewTunnel(tunnelUrl: String): NewTunnel
        interface NewTunnel {
            val routingId: ByteArray   // 3 bytes, from X-caBLE-Shard
            val channel: Channel       // Noise transport, after handshake
        }
        interface Channel {
            fun send(plaintext: ByteArray)
            fun receive(): ByteArray
            fun close()
        }
    }

    data class Keys(val eid: ByteArray, val tunnelId: ByteArray, val psk: ByteArray)

    fun deriveKeys(qr: FidoQr): Keys {
        val salt = ByteArray(0)
        val eidKeyMaterial = hkdf(qr.qrSecret, salt, byteArrayOf(1, 0, 0, 0), 64)
        val aesKey = eidKeyMaterial.copyOfRange(0, 32)
        val hmacKey = eidKeyMaterial.copyOfRange(32, 64)
        val tunnelId = hkdf(qr.qrSecret, salt, byteArrayOf(2, 0, 0, 0), 16)
        // psk is derived in authenticate() once the EID plaintext exists,
        // because the BLE advert plaintext is its HKDF salt.
        val eidPayload = buildEidPlaintext(aesKey, hmacKey, ByteArray(3)).let { encryptEid(aesKey, hmacKey, it) }
        return Keys(eidPayload, tunnelId, ByteArray(0))
    }

    /**
     * Build the 20-byte EID payload. The plaintext layout is:
     *   byte 0: 0x00
     *   bytes 1-10: 10-byte nonce
     *   bytes 11-13: routing ID (3 bytes, from X-caBLE-Shard)
     *   bytes 14-15: tunnel server domain (big-endian, 0 for cable.ua5v.com)
     */
    /**
     * Build the 16-byte EID plaintext. Layout per Chromium FromComponents:
     *   1 (0x00) + 10 (nonce) + 3 (routing_id) + 2 (domain) = 16.
     * The plaintext is also the HKDF salt for the Noise PSK.
     */
    fun buildEidPlaintext(aesKey: ByteArray, hmacKey: ByteArray, routingId: ByteArray): ByteArray {
        require(routingId.size == 3) { "routingId must be 3 bytes" }
        val plaintextEid = ByteArray(16)
        plaintextEid[0] = 0
        val nonce = ByteArray(10)
        SecureRandom().nextBytes(nonce)
        System.arraycopy(nonce, 0, plaintextEid, 1, 10)
        System.arraycopy(routingId, 0, plaintextEid, 11, 3)
        // bytes 14-15 already zero (domain 0)
        return plaintextEid
    }

    /** AES-ECB the plaintext with aesKey, HMAC-SHA256 the ciphertext with hmacKey,
     *  return the 20-byte BLE payload: 16-byte ciphertext || 4-byte HMAC tag. */
    fun encryptEid(aesKey: ByteArray, hmacKey: ByteArray, plaintextEid: ByteArray): ByteArray {
        require(plaintextEid.size == 16) { "EID plaintext must be 16 bytes" }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val ciphertext = cipher.doFinal(plaintextEid)

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        val hmac = mac.doFinal(ciphertext)
        return ciphertext + hmac.copyOfRange(0, 4)
    }

    /**
     * Runs the whole exchange for [qr]. Which passkey signs is decided by
     * [chooser] once the browser's request has arrived; nothing is signed
     * before it returns [CtapAuthenticator.Decision.Sign].
     */
    fun authenticate(qr: FidoQr, chooser: CtapAuthenticator.Chooser): ByteArray {
        val salt = ByteArray(0)
        val eidKeyMaterial = hkdf(qr.qrSecret, salt, byteArrayOf(1, 0, 0, 0), 64)
        val aesKey = eidKeyMaterial.copyOfRange(0, 32)
        val hmacKey = eidKeyMaterial.copyOfRange(32, 64)
        val tunnelId = hkdf(qr.qrSecret, salt, byteArrayOf(2, 0, 0, 0), 16)

        // 1. Connect /cable/new/ FIRST. The WebSocket must open before we advertise,
        //    because the routing ID comes from the response headers.
        val newTunnelUrl = "wss://cable.ua5v.com/cable/new/" + tunnelId.joinToString("") { "%02x".format(it) }

        // Inject peer identity so NoiseTunnelClient can build its state. PSK is
        // injected after the EID plaintext exists, because the plaintext is its salt.
        val peer65 = it.snel.passkeychain.hybrid.NoiseTunnelClient.decompressPeerIdentity(qr.peerPublicKey)
        it.snel.passkeychain.hybrid.NoiseTunnelClient.STATIC_PEER_IDENTITY = peer65

        // Responder's static keypair. Its public half is the QR's peerPublicKey;
        // the private half is derived from qrSecret so both sides agree. Best-guess
        // info label [4,0,0,0]; the next handshake run will confirm whether the
        // es DH succeeds, by whether msg1 decrypts.
        val staticPrivSeed = hkdf(qr.qrSecret, salt, byteArrayOf(4, 0, 0, 0), 32)
        val staticPrivPkcs8 = p256PrivateKeyFromScalar(staticPrivSeed)
        it.snel.passkeychain.hybrid.NoiseTunnelClient.STATIC_RESPONDER_PRIV = staticPrivPkcs8

        progress(Progress.TunnelOpening(java.net.URI(newTunnelUrl).host))
        val newTunnel = tunnel.connectNewTunnel(newTunnelUrl)
        progress(Progress.TunnelOpen)
        val routingId = newTunnel.routingId

        // 2. Build the 16-byte EID plaintext. Its bytes are the HKDF salt for the PSK.
        val eidPlaintext = buildEidPlaintext(aesKey, hmacKey, routingId)
        // 3. Derive the Noise PSK: HKDF(qrSecret, salt=eidPlaintext, info=[3,0,0,0]).
        val psk = hkdf(qr.qrSecret, eidPlaintext, byteArrayOf(3, 0, 0, 0), 32)
        it.snel.passkeychain.hybrid.NoiseTunnelClient.STATIC_PSK = psk
        it.snel.passkeychain.hybrid.NoiseTunnelClient.STATIC_EID_PLAINTEXT = eidPlaintext
        it.snel.passkeychain.util.Dbg.d("HybridTransport", "authenticate: eidPlaintext = " + eidPlaintext.joinToString("") { "%02x".format(it) })
        it.snel.passkeychain.util.Dbg.d("HybridTransport", "authenticate: psk          = " + psk.joinToString("") { "%02x".format(it) })
        it.snel.passkeychain.util.Dbg.d("HybridTransport", "authenticate: peerIdentity = " + peer65.joinToString("") { "%02x".format(it) })
        // 4. Encrypt the EID and advertise it.
        val eid = encryptEid(aesKey, hmacKey, eidPlaintext)
        ble.advertise(UUID.fromString("0000FFF9-0000-1000-8000-00805F9B34FB"), eid)
        progress(Progress.Broadcasting)

        try {
            // 3. Wait for the Noise handshake + CTAP2 request on the already-open WebSocket.
            val channel = newTunnel.channel
            val request = channel.receive()
            val response = CtapAuthenticator.handle(request, chooser)
            channel.send(response)
            channel.close()
            return response
        } finally {
            ble.stop()
        }
    }

    /** Signs [ctapRequest] with [passkey] without asking anyone; for tests. */
    fun buildGetAssertionResponse(ctapRequest: ByteArray, passkey: Passkey): ByteArray =
        CtapAuthenticator.handle(ctapRequest) { CtapAuthenticator.Decision.Sign(passkey) }

    private fun hexOf(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun b64urlToBytes(s: String): ByteArray = it.snel.passkeychain.util.B64.dUrl(s)

    companion object {
        /** Derive a P-256 private key (PKCS#8 DER) from a 32-byte scalar. */
        fun p256PrivateKeyFromScalar(scalar: ByteArray): ByteArray {
            require(scalar.size == 32) { "scalar must be 32 bytes" }
            val params = java.security.AlgorithmParameters.getInstance("EC")
                .apply { init(java.security.spec.ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
            val d = java.math.BigInteger(1, scalar)
            val priv = java.security.KeyFactory.getInstance("EC")
                .generatePrivate(java.security.spec.ECPrivateKeySpec(d, params))
            return priv.encoded
        }

        fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
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
        private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    }
}
