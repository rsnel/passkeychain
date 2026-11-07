package it.snel.passkeychain.hybrid

import java.util.UUID
import it.snel.passkeychain.model.Passkey
import java.security.SecureRandom
import javax.crypto.Cipher
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
         * X-Cable-Routing-Id response header. The WebSocket must remain open
         * and ready to send/receive Noise handshake bytes.
         */
        fun connectNewTunnel(tunnelUrl: String): NewTunnel
        interface NewTunnel {
            val routingId: ByteArray   // 3 bytes, from X-Cable-Routing-Id
            /**
             * The Noise channel on this WebSocket, for the browser whose QR key is
             * [peerIdentity65] (uncompressed P-256) and the [psk] derived from the
             * advertised EID. The handshake runs on the first receive().
             */
            fun open(peerIdentity65: ByteArray, psk: ByteArray): Channel
        }
        interface Channel {
            fun send(plaintext: ByteArray)
            fun receive(): ByteArray
            fun close()
        }
    }

    /**
     * The 16-byte EID plaintext (Chromium eid::FromComponents):
     *   byte 0: 0x00 | bytes 1-10: random nonce | bytes 11-13: routing ID |
     *   bytes 14-15: tunnel server domain (0 = cable.ua5v.com).
     * The same bytes are the HKDF salt for the Noise PSK.
     */
    fun buildEidPlaintext(routingId: ByteArray): ByteArray {
        require(routingId.size == 3) { "routingId must be 3 bytes" }
        val plaintextEid = ByteArray(16)
        val nonce = ByteArray(10)
        SecureRandom().nextBytes(nonce)
        System.arraycopy(nonce, 0, plaintextEid, 1, 10)
        System.arraycopy(routingId, 0, plaintextEid, 11, 3)
        // byte 0 and bytes 14-15 stay zero
        return plaintextEid
    }

    /**
     * The 20-byte BLE payload: AES-256-ECB of the one-block plaintext with the
     * full 32-byte [aesKey], then the first 4 bytes of HMAC-SHA256(key = hmacKey,
     * message = ciphertext).
     */
    fun encryptEid(aesKey: ByteArray, hmacKey: ByteArray, plaintextEid: ByteArray): ByteArray {
        require(aesKey.size == 32) { "EID AES key must be 32 bytes (AES-256)" }
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
        // HKDF labels (Chromium DerivedValueType): 1 EID key, 2 tunnel ID, 3 PSK
        val eidKeyMaterial = hkdf(qr.qrSecret, ByteArray(0), label(1), 64)
        val aesKey = eidKeyMaterial.copyOfRange(0, 32)
        val hmacKey = eidKeyMaterial.copyOfRange(32, 64)
        val tunnelId = hkdf(qr.qrSecret, ByteArray(0), label(2), 16)
        val peer65 = NoiseTunnelClient.decompressPeerIdentity(qr.peerPublicKey)

        // 1. Open /cable/new/ first: the routing ID for the advert comes from its response headers.
        val newTunnelUrl = "wss://cable.ua5v.com/cable/new/" + tunnelId.joinToString("") { "%02x".format(it) }
        progress(Progress.TunnelOpening(java.net.URI(newTunnelUrl).host))
        val newTunnel = tunnel.connectNewTunnel(newTunnelUrl)
        progress(Progress.TunnelOpen)

        // 2. The EID plaintext, and from exactly those bytes the Noise PSK.
        val eidPlaintext = buildEidPlaintext(newTunnel.routingId)
        val psk = hkdf(qr.qrSecret, eidPlaintext, label(3), 32)
        it.snel.passkeychain.util.Dbg.d("HybridTransport", "authenticate: eidPlaintext = " + eidPlaintext.joinToString("") { "%02x".format(it) })
        it.snel.passkeychain.util.Dbg.d("HybridTransport", "authenticate: psk          = " + psk.joinToString("") { "%02x".format(it) })
        it.snel.passkeychain.util.Dbg.d("HybridTransport", "authenticate: peerIdentity = " + peer65.joinToString("") { "%02x".format(it) })

        // 3. Advertise the encrypted EID: proof to the browser that this phone is nearby.
        ble.advertise(UUID.fromString("0000FFF9-0000-1000-8000-00805F9B34FB"), encryptEid(aesKey, hmacKey, eidPlaintext))
        progress(Progress.Broadcasting)

        try {
            // 4. Noise handshake (on the first receive), then one CTAP2 request and its answer.
            val channel = newTunnel.open(peer65, psk)
            val request = channel.receive()
            val response = CtapAuthenticator.handle(request, chooser)
            channel.send(response)
            channel.close()
            return response
        } finally {
            ble.stop()
        }
    }

    private fun label(n: Int) = byteArrayOf(n.toByte(), 0, 0, 0)

    /** Signs [ctapRequest] with [passkey] without asking anyone; for tests. */
    fun buildGetAssertionResponse(ctapRequest: ByteArray, passkey: Passkey): ByteArray =
        CtapAuthenticator.handle(ctapRequest) { CtapAuthenticator.Decision.Sign(passkey) }

    companion object {
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
    }
}
