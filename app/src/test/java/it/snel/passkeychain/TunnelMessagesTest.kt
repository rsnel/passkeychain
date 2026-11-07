package it.snel.passkeychain

import it.snel.passkeychain.hybrid.TunnelMessages
import it.snel.passkeychain.hybrid.TunnelMessages.Incoming
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The forms in which browser messages arrive (docs/PROTOCOL.md, section 12). */
class TunnelMessagesTest {

    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun ctap(m: Incoming): ByteArray = (m as? Incoming.Ctap)?.command ?: throw AssertionError("expected CTAP, got $m")

    @Test fun bareGetAssertionIsCtap() {
        // 0x02 followed by a CBOR map: getAssertion as Chrome sends it, not kShutdown
        assertArrayEquals(b(0x02, 0xA1, 0x01, 0x61, 0x61), ctap(TunnelMessages.classify(b(0x02, 0xA1, 0x01, 0x61, 0x61))))
    }

    @Test fun prefixedCommandLosesItsPrefix() {
        assertArrayEquals(b(0x01, 0xA0), ctap(TunnelMessages.classify(b(0x00, 0x01, 0xA0))))  // makeCredential probe
        assertArrayEquals(b(0x02, 0xA0), ctap(TunnelMessages.classify(b(0x00, 0x02, 0xA0))))
        assertArrayEquals(b(0x04), ctap(TunnelMessages.classify(b(0x00, 0x04))))              // prefixed getInfo
    }

    @Test fun bareGetInfoIsCtap() {
        assertArrayEquals(b(0x04), ctap(TunnelMessages.classify(b(0x04))))
    }

    @Test fun oneByteShutdownEndsTheSignIn() {
        assertTrue(TunnelMessages.classify(b(0x02)) == Incoming.Shutdown)
    }

    @Test fun updatesJsonEmptyAndUnknownAreIgnored() {
        assertTrue(TunnelMessages.classify(b(0x03)) is Incoming.Ignore)                 // kUpdate
        assertTrue(TunnelMessages.classify(b(0x01, 0x7B, 0x7D)) is Incoming.Ignore)     // kJSON "{}"
        assertTrue(TunnelMessages.classify(ByteArray(0)) is Incoming.Ignore)
        assertTrue(TunnelMessages.classify(b(0x09, 0x09)) is Incoming.Ignore)
        assertTrue(TunnelMessages.classify(b(0x07)) is Incoming.Ignore)
    }
}
