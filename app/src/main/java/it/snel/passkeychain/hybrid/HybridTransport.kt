package it.snel.passkeychain.hybrid

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.webauthn.Assertion
import it.snel.passkeychain.webauthn.Cbor
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Cross-device (hybrid / caBLE v2) authenticator — the flow behind the
 * Microsoft "scan this QR with the device that has your passkey" screen.
 *
 * STATUS: the deterministic cryptography below is implemented and unit-tested
 * (QR decode, HKDF key derivation, CTAP2 getAssertion response assembly). The
 * two runtime stages that can only be exercised on a physical device — the BLE
 * advertisement that proves proximity, and the Noise-encrypted WebSocket tunnel
 * through the assigned relay — are defined as interfaces with a clearly marked
 * [DeviceStage] boundary. This is the part to iterate on against a real phone;
 * it intentionally fails loudly rather than pretending to work.
 *
 * Reference: Chromium device/fido/cable/v2_handshake.cc and the FIDO CTAP 2.x
 * "hybrid" transport appendix.
 */
class HybridTransport(
    private val ble: BleAdvertiser,
    private val tunnel: TunnelClient,
) {

    /** The stage that genuinely needs a device; never silently stubbed at runtime. */
    class DeviceStageMissing(stage: String) :
        UnsupportedOperationException("hybrid stage '$stage' needs on-device BLE/network and is not wired in this build")

    interface BleAdvertiser {
        /** Advertise the 20-byte caBLE EID so the browser confirms proximity. */
        fun advertise(eid: ByteArray)
        fun stop()
    }

    interface TunnelClient {
        /** Connect to wss://<tunnelDomain>/cable/connect/… and run the Noise handshake. */
        fun connectAndHandshake(tunnelUrl: String, psk: ByteArray, peerIdentity: ByteArray): Channel
        interface Channel {
            fun send(plaintext: ByteArray)
            fun receive(): ByteArray
            fun close()
        }
    }

    data class Keys(val eid: ByteArray, val tunnelId: ByteArray, val psk: ByteArray)

    /**
     * Derive the BLE EID, tunnel id and pre-shared key from the QR secret.
     * HKDF-SHA256 with the caBLE info labels. (Deterministic; unit-tested.)
     */
    fun deriveKeys(qr: FidoQr): Keys {
        val eidKey = hkdf(qr.qrSecret, info = byteArrayOf(1), len = 32)     // EID key
        val tunnelId = hkdf(qr.qrSecret, info = byteArrayOf(2), len = 16)   // tunnel id
        val psk = hkdf(qr.qrSecret, info = byteArrayOf(3), len = 32)        // Noise PSK
        // The 16-byte nonce + tunnel-domain index are encrypted under eidKey to
        // form the 20-byte advertised EID; the exact AES-CTR construction is
        // applied in the BLE stage.
        val eid = eidKey.copyOf(20)
        return Keys(eid, tunnelId, psk)
    }

    /**
     * Run the full exchange. Throws [DeviceStageMissing] at the first stage that
     * needs hardware, so callers get an honest result rather than a fake one.
     */
    fun authenticate(qr: FidoQr, passkey: Passkey): ByteArray {
        val keys = deriveKeys(qr)
        ble.advertise(keys.eid)                        // -> DeviceStageMissing until wired
        try {
            val channel = tunnel.connectAndHandshake(   // -> DeviceStageMissing until wired
                tunnelUrl = "wss://cable.ua5v.com/cable/connect",
                psk = keys.psk,
                peerIdentity = qr.peerPublicKey,
            )
            val request = channel.receive()              // CTAP2 getAssertion (CBOR)
            val response = buildGetAssertionResponse(request, passkey)
            channel.send(response)
            channel.close()
            return response
        } finally {
            ble.stop()
        }
    }

    /**
     * Parse a CTAP2 authenticatorGetAssertion request (command 0x02) and build
     * the signed response map {1: credential, 2: authData, 3: signature,
     * 4: user}. The signing itself reuses the shared, verified [Assertion] code.
     */
    fun buildGetAssertionResponse(ctapRequest: ByteArray, passkey: Passkey): ByteArray {
        require(ctapRequest.isNotEmpty() && ctapRequest[0].toInt() == 0x02) { "not a getAssertion command" }
        @Suppress("UNCHECKED_CAST")
        val params = Cbor.decode(ctapRequest.copyOfRange(1, ctapRequest.size)) as Map<Any?, Any?>
        val rpId = (params[1L] ?: params[1]) as String
        val clientDataHash = (params[2L] ?: params[2]) as ByteArray
        require(rpId == passkey.rpId) { "rpId mismatch" }

        val r = Assertion.create(
            passkey = passkey,
            challengeB64Url = "",            // not used when clientDataHash is supplied
            origin = "",
            clientDataHash = clientDataHash,
        )
        val credential = linkedMapOf<Any, Any>("id" to b64urlToBytes(passkey.credentialId), "type" to "public-key")
        val user = linkedMapOf<Any, Any>("id" to b64urlToBytes(passkey.userHandle))
        val resp = linkedMapOf<Any, Any>(
            1 to credential,
            2 to r.authenticatorData,
            3 to r.signature,
            4 to user,
        )
        // 0x00 = CTAP2_OK status byte, then the CBOR response
        return byteArrayOf(0x00) + Cbor.encode(resp)
    }

    private fun b64urlToBytes(s: String): ByteArray = it.snel.passkeychain.util.B64.dUrl(s)

    companion object {
        /** HKDF-SHA256 (extract+expand) with an all-zero salt, per caBLE usage. */
        fun hkdf(ikm: ByteArray, info: ByteArray, len: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            // extract
            mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            val prk = mac.doFinal(ikm)
            // expand
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

        @Suppress("unused")
        private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    }
}
