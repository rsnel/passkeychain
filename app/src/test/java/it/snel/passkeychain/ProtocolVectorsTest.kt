package it.snel.passkeychain

import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.hybrid.HybridTransport
import it.snel.passkeychain.hybrid.NoiseHandshake
import it.snel.passkeychain.hybrid.TunnelDomains
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The test vectors of docs/PROTOCOL.md section 18 (computed independently by
 * docs/protocol-vectors.py): QR decoding, the keys derived from the QR secret,
 * the advert and the psk. The Noise and transport vectors are checked by
 * NoiseHandshakeTest.
 */
class ProtocolVectorsTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun label(n: Int) = byteArrayOf(n.toByte(), 0, 0, 0)
    private val secret = ByteArray(16) { it.toByte() }

    @Test fun qrCode() {
        val qr = FidoQr.parse(QR_TEXT)
        assertArrayEquals(hex("020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"), qr.peerPublicKey)
        assertArrayEquals(secret, qr.qrSecret)
        assertEquals(2, qr.knownDomainCount)
        assertEquals(1794135600L, qr.timestamp)
        assertEquals(false, qr.stateAssisted)
        assertEquals("ga", qr.hint)
        // and the QR key decompresses to the s_i of the Noise vector
        assertArrayEquals(hex(S_I), NoiseHandshake.decompress(qr.peerPublicKey))
    }

    @Test fun keysFromTheQrSecret() {
        val eid = HybridTransport.hkdf(secret, ByteArray(0), label(1), 64)
        assertArrayEquals(hex(AES), eid.copyOfRange(0, 32))
        assertArrayEquals(hex(HMAC), eid.copyOfRange(32, 64))
        assertArrayEquals(hex(TUNNEL), HybridTransport.hkdf(secret, ByteArray(0), label(2), 16))
    }

    @Test fun advertAndPsk() {
        val t = HybridTransport(
            object : HybridTransport.BleAdvertiser {
                override fun advertise(serviceUuid: java.util.UUID, payload: ByteArray) {}
                override fun stop() {}
            },
            object : HybridTransport.TunnelClient {
                override fun connectNewTunnel(tunnelUrl: String) = throw UnsupportedOperationException()
            },
        )
        for ((domain, plain, advert) in listOf(Triple(0, PLAIN0, ADV0), Triple(266, PLAIN266, ADV266))) {
            // the app's own plaintext, with the vector's random part
            val p = t.buildEidPlaintext(hex("c0ffee"), domain)
            System.arraycopy(hex(plain), 1, p, 1, 10)
            assertArrayEquals("plaintext, domain $domain", hex(plain), p)
            assertArrayEquals("advert, domain $domain", hex(advert), t.encryptEid(hex(AES), hex(HMAC), p))
        }
        assertArrayEquals(hex(PSK), HybridTransport.hkdf(secret, hex(PLAIN0), label(3), 32))
    }

    @Test fun tunnelServerNames() {
        assertEquals("cable.qz2ekwmnd332c.info", TunnelDomains.hostname(256))
        assertEquals("cable.wufkweyy3uaxb.com", TunnelDomains.hostname(266))
    }

    private companion object {
        const val QR_TEXT = "FIDO:/064761326369506941132196635817367045715076129656615309261485932746823659474011834762800564050807352788025421010491811870057950297627316213606389454340866107096654083076"
        const val S_I = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
        const val AES = "d06e92859fa9afce38139c04dae7f64196acfdb9a28dffb326f3a8f2cc0788e2"
        const val HMAC = "28bd73c3484f2f7de169d9b087c30e6f409e70bc86f5d65e03d762b4b0df2af7"
        const val TUNNEL = "de1d8150b45f03349b2b00a52e2e893e"
        const val PLAIN0 = "00a0a1a2a3a4a5a6a7a8a9c0ffee0000"
        const val PLAIN266 = "00a0a1a2a3a4a5a6a7a8a9c0ffee0a01"
        const val ADV0 = "94198c8ba6d8f263ce372e5a84b41f31e66db611"
        const val ADV266 = "783741baf316f77f3770a0e3e4384f0160c177f9"
        const val PSK = "7cc9adc8f8a4663be4c0e4cda5b44a9c38369d5309e73b6b446d3096f551641d"
    }
}
