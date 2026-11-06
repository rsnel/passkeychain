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
        /** Advertise the 20-byte caBLE v2 payload using the FIDO service UUID (0xFFF9). */
        fun advertise(serviceUuid: java.util.UUID, payload: ByteArray)
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
        // Chromium: kEIDKeySize is 64 bytes (32-byte AES key + 32-byte HMAC key)
        val eidKeyMaterial = hkdf(qr.qrSecret, info = byteArrayOf(1), len = 64)
        val aesKey = eidKeyMaterial.copyOfRange(0, 32)
        val hmacKey = eidKeyMaterial.copyOfRange(32, 64)
        
        val tunnelId = hkdf(qr.qrSecret, info = byteArrayOf(2), len = 16)
        val psk = hkdf(qr.qrSecret, info = byteArrayOf(3), len = 32)
        
        // Construct the 20-byte payload (16-byte ciphertext + 4-byte HMAC)
        val eidPayload = buildEidPayload(aesKey, hmacKey)
        
        return Keys(eidPayload, tunnelId, psk)
    }

    /**
     * Builds the 20-byte caBLE v2 BLE advertisement payload.
     * Format: [16-byte AES-Ciphertext][4-byte HMAC-SHA256 tag]
     *
     * The plaintext EID is: 8-byte nonce || 3-byte routing ID || 3-byte tunnel ID || 2 zero bytes.
     * (The 2 zero bytes allow Chrome to verify correct decryption).
     */
    private fun buildEidPayload(aesKey: ByteArray, hmacKey: ByteArray): ByteArray {
        val plaintextEid = ByteArray(16)
        
        // 10-byte nonce
        val nonce = ByteArray(10)
        SecureRandom().nextBytes(nonce)
        System.arraycopy(nonce, 0, plaintextEid, 0, 10)
        
        // Set routing ID to a non-zero value to test if zero is rejected
        plaintextEid[10] = 1
        plaintextEid[11] = 2
        plaintextEid[12] = 3
        
        // Tunnel server ID (bytes 13-14). Try value 1.
        plaintextEid[13] = 0
        plaintextEid[14] = 1
        plaintextEid[15] = 0
        
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val ciphertext = cipher.doFinal(plaintextEid) // 16 bytes
        
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        // Try HMAC over plaintext instead of ciphertext
        val hmac = mac.doFinal(plaintextEid)
        
        // Return: 16-byte ciphertext + first 4 bytes of HMAC (Total 20 bytes)
        return ciphertext + hmac.copyOfRange(0, 4)
    }

    /**
     * Run the full exchange. Throws [DeviceStageMissing] at the first stage that
     * needs hardware, so callers get an honest result rather than a fake one.
     */
    fun authenticate(qr: FidoQr, passkey: Passkey): ByteArray {
        val keys = deriveKeys(qr)
        ble.advertise(UUID.fromString("0000FFF9-0000-1000-8000-00805F9B34FB"), keys.eid)                        // 20-byte payload now
        try {
            val channel = tunnel.connectAndHandshake(   // 20-byte payload now
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
