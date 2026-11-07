package it.snel.passkeychain

import it.snel.passkeychain.hybrid.NoiseCrypter
import it.snel.passkeychain.hybrid.NoiseHandshake
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Noise handshake and transport encryption of the hybrid sign-in, against
 * a vector computed independently in Python (the 'cryptography' package):
 * a browser-side initiator writes msg1 and checks msg2, a responder writes
 * msg2, and both must agree on the handshake hash. Fixed keys:
 * s_i = 0x11..11 (the browser's QR key), e_i = 0x22..22, e_r = 0x33..33,
 * psk = 00 01 .. 1f.
 */
class NoiseHandshakeTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private val ephemeralR get() = NoiseHandshake.keyPair(ByteArray(32) { 0x33 }, hex(E_R_PUB))

    @Test fun qrKeyDecompresses() {
        assertArrayEquals(hex(S_I), NoiseHandshake.decompress(hex(S_I_COMPRESSED)))
    }

    @Test fun handshakeMatchesVector() {
        val r = NoiseHandshake(hex(S_I), hex(PSK), ephemeralR).respond(hex(MSG1))
        assertArrayEquals("msg2", hex(MSG2), r.msg2)
        assertArrayEquals("receive key = first Split key", hex(K1), r.receiveKey)
        assertArrayEquals("send key = second Split key", hex(K2), r.sendKey)
        assertArrayEquals("handshake hash", hex(H), r.handshakeHash)
    }

    @Test fun transportMatchesVector() {
        val c = NoiseCrypter(receiveKey = hex(K1), sendKey = hex(K2))
        assertArrayEquals("first record, counter 0", hex(TX0), c.encrypt(byteArrayOf(0x00, 0xA0.toByte())))
        assertArrayEquals("second record, counter 1", hex(TX1), c.encrypt(ByteArray(40) { 'x'.code.toByte() }))
        assertArrayEquals(byteArrayOf(0x02, 0xA1.toByte(), 0x01, 0x61, 0x61), c.decrypt(hex(RX0)))
    }

    @Test fun wrongPskIsRejected() {
        val psk = hex(PSK).also { it[31] = (it[31].toInt() xor 1).toByte() }
        assertThrows<NoiseHandshake.Failed> { NoiseHandshake(hex(S_I), psk, ephemeralR).respond(hex(MSG1)) }
    }

    @Test fun wrongQrKeyIsRejected() {
        // the handshake hash covers the browser's static key: another key, no handshake
        val other = NoiseHandshake.uncompressed(NoiseHandshake.newEphemeral().public as java.security.interfaces.ECPublicKey)
        assertThrows<NoiseHandshake.Failed> { NoiseHandshake(other, hex(PSK), ephemeralR).respond(hex(MSG1)) }
    }

    @Test fun offCurveKeyInMsg1IsRejected() {
        val msg1 = hex(MSG1).also { it[64] = (it[64].toInt() xor 1).toByte() } // last byte of y
        assertThrows<NoiseHandshake.Failed> { NoiseHandshake(hex(S_I), hex(PSK), ephemeralR).respond(msg1) }
    }

    @Test fun shortMsg1IsRejected() {
        assertThrows<NoiseHandshake.Failed> { NoiseHandshake(hex(S_I), hex(PSK), ephemeralR).respond(hex(MSG1).copyOf(80)) }
    }

    @Test fun tamperedRecordIsRejected() {
        val rx = hex(RX0).also { it[5] = (it[5].toInt() xor 0x40).toByte() }
        assertThrows<Exception> { NoiseCrypter(hex(K1), hex(K2)).decrypt(rx) }
    }

    @Test fun recordsMustArriveInOrder() {
        // the receive counter starts at 0: a record sealed with counter 1 does not open first
        val sender = NoiseCrypter(receiveKey = hex(K2), sendKey = hex(K1))
        sender.encrypt(byteArrayOf(1))
        val second = sender.encrypt(byteArrayOf(2))
        assertThrows<Exception> { NoiseCrypter(hex(K1), hex(K2)).decrypt(second) }
    }

    @Test fun handshakeRunsOnce() {
        val hs = NoiseHandshake(hex(S_I), hex(PSK), ephemeralR)
        hs.respond(hex(MSG1))
        assertThrows<IllegalStateException> { hs.respond(hex(MSG1)) }
    }

    @Test fun freshEphemeralsGiveFreshKeys() {
        // with a random ephemeral the handshake still works, but msg2 and keys differ from the vector
        val r = NoiseHandshake(hex(S_I), hex(PSK)).respond(hex(MSG1))
        assertEquals(81, r.msg2.size)
        assertTrue(!r.sendKey.contentEquals(hex(K2)))
    }

    @Test fun postHandshakePaddingIs512Bytes() {
        val padded = NoiseCrypter.padPostHandshake(ByteArray(100) { 7 })
        assertEquals(512, padded.size)
        assertEquals(410, (padded[510].toInt() and 0xFF) or ((padded[511].toInt() and 0xFF) shl 8))
        assertEquals(1024, NoiseCrypter.padPostHandshake(ByteArray(511)).size)
    }

    private inline fun <reified T : Throwable> assertThrows(block: () -> Unit) {
        try {
            block()
        } catch (e: Throwable) {
            if (e is T) return
            throw AssertionError("expected ${T::class.java.simpleName}, got $e")
        }
        throw AssertionError("expected ${T::class.java.simpleName}, nothing was thrown")
    }

    private companion object {
        const val S_I_COMPRESSED = "020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
        const val S_I = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
        const val E_R_PUB = "0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a1"
        const val PSK = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        const val MSG1 = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c912850b5cdd7aad2f31288946b97b9bf4ff30"
        const val MSG2 = "0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a10bbf8dd558164c71c16b2efd758a64b3"
        const val K1 = "c736eed4e03cdfd00c86ed2315762dcf191196e7de0d9e000cd02c40d5043934"
        const val K2 = "d96ef52dcaf9deb0e52e8c08d5cca5793fcd2d9ed509f5be27974c8573e9467c"
        const val H = "5279b5a75e774b9db7607132ca0695a87db5b54aa922ab897b536168f5dce415"
        const val TX0 = "711ee11d8f612de52bfffbe608bfd0ba02179546c6612e8cf46f2fb412caade1e17b0ff77d7f0de4a5ec2551c2f9d2dd"
        const val TX1 = "cefab81e86b9b90afc1d09e693f16f4c2e429c7e2711b1c13e277926a38f1d3b3d8eb6f5949a3d48b1b871cbe1db24027a3fb81a6db234bdb2302a53c3a91482fbce1db6256440fb3b4748717eee1cdd"
        const val RX0 = "e6d80410f66e95b9d5b8a4388bd9db846fab9a36fee839a1d7345f64bf3240eda18c96d881084ca73a200c2b58af36dd"
    }
}
