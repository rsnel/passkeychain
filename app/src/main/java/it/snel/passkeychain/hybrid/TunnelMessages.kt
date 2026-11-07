package it.snel.passkeychain.hybrid

/**
 * What a decrypted message from the browser is (docs/PROTOCOL.md, section 12).
 * Chrome sends CTAP2 requests with or without a MessageType prefix, so the
 * forms seen in practice are recognised here; pure, so it can be unit-tested.
 */
object TunnelMessages {

    sealed interface Incoming {
        /** a CTAP2 command: command byte followed by its CBOR parameters (if any) */
        class Ctap(val command: ByteArray) : Incoming
        /** MessageType kShutdown: the browser ends the sign-in */
        data object Shutdown : Incoming
        /** something to skip: kUpdate, kJSON, empty or unknown */
        class Ignore(val why: String) : Incoming
    }

    private const val TYPE_CTAP = 0x00
    private const val TYPE_JSON = 0x01
    private const val TYPE_SHUTDOWN = 0x02
    private const val TYPE_UPDATE = 0x03

    fun classify(pt: ByteArray): Incoming {
        if (pt.isEmpty()) return Incoming.Ignore("empty message")
        val first = pt[0].toInt() and 0xFF
        val second = if (pt.size >= 2) pt[1].toInt() and 0xFF else -1
        if (pt.size == 1) return when (first) {
            TYPE_SHUTDOWN -> Incoming.Shutdown
            TYPE_UPDATE -> Incoming.Ignore("kUpdate")
            // authenticatorGetInfo has no parameters: a bare 0x04
            CtapAuthenticator.CMD_GET_INFO -> Incoming.Ctap(pt)
            else -> Incoming.Ignore("unknown one-byte message 0x%02x".format(first))
        }
        // MessageType kCTAP prefix, then a CTAP2 command byte
        if (first == TYPE_CTAP && second in 0x01..0x04) return Incoming.Ctap(pt.copyOfRange(1, pt.size))
        // a bare CTAP2 command followed by a CBOR map (getAssertion as Chrome sends it)
        if (first in 0x01..0x04 && second in 0xA0..0xBF) return Incoming.Ctap(pt)
        if (first == TYPE_JSON) return Incoming.Ignore("kJSON")
        return Incoming.Ignore("unrecognized message 0x%02x, %d bytes".format(first, pt.size))
    }
}
