package it.snel.passkeychain

import it.snel.passkeychain.hybrid.CtapAuthenticator
import it.snel.passkeychain.hybrid.FidoQr
import it.snel.passkeychain.hybrid.HybridTransport
import it.snel.passkeychain.hybrid.TunnelDomains
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/** How the hybrid exchange behaves around the tunnel: cleanup on every path, and the request loop. */
class HybridTransportTest {

    /** A QR whose key is a real P-256 point (the one from NoiseHandshakeTest's vector). */
    private val qr = FidoQr(
        peerPublicKey = ByteArray(33).also {
            val hex = "020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
            for (i in it.indices) it[i] = hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        },
        qrSecret = ByteArray(16) { it.toByte() },
        knownDomainCount = 2, timestamp = 0, stateAssisted = false, hint = "ga",
    )

    private class FakeBle : HybridTransport.BleAdvertiser {
        var started = 0; var stopped = 0
        override fun advertise(serviceUuid: UUID, payload: ByteArray) { started++ }
        override fun stop() { stopped++ }
    }

    /** A tunnel that hands out [requests] in turn, then fails like a closed connection. */
    private class FakeTunnel(private val requests: List<ByteArray>) : HybridTransport.TunnelClient {
        val sent = mutableListOf<ByteArray>()
        var closed = 0
        override fun connectNewTunnel(tunnelUrl: String) = object : HybridTransport.TunnelClient.NewTunnel {
            override val routingId = byteArrayOf(1, 2, 3)
            override fun close() { closed++ }
            override fun open(peerIdentity65: ByteArray, psk: ByteArray) = object : HybridTransport.TunnelClient.Channel {
                var next = 0
                override fun receive(): ByteArray =
                    requests.getOrNull(next++) ?: throw HybridTransport.SignInFailure("The computer ended the sign-in.")
                override fun send(plaintext: ByteArray) { sent += plaintext }
                override fun close() { closed++ }
            }
        }
    }

    private fun getAssertion(): ByteArray =
        byteArrayOf(0x02) + it.snel.passkeychain.webauthn.Cbor.encode(mapOf<Any, Any>(1 to "example.com", 2 to ByteArray(32)))

    @Test fun answersEarlierRequestsUntilTheGetAssertion() {
        // a makeCredential probe and a getInfo come first; both are answered, then the getAssertion
        val probe = byteArrayOf(0x01) + it.snel.passkeychain.webauthn.Cbor.encode(mapOf<Any, Any>(1 to ByteArray(32)))
        val tunnel = FakeTunnel(listOf(probe, byteArrayOf(0x04), getAssertion()))
        val ble = FakeBle()
        val response = HybridTransport(ble, tunnel).authenticate(qr) { CtapAuthenticator.Decision.NoCredentials }
        assertEquals(3, tunnel.sent.size)
        assertEquals(CtapAuthenticator.CTAP2_ERR_NO_CREDENTIALS.toByte(), tunnel.sent[0][0]) // probe
        assertEquals(CtapAuthenticator.CTAP2_OK.toByte(), tunnel.sent[1][0])                  // getInfo
        assertEquals(CtapAuthenticator.CTAP2_ERR_NO_CREDENTIALS.toByte(), response[0])        // no passkey for example.com
        assertEquals(1, ble.stopped)
        assertTrue(tunnel.closed >= 1)
    }

    @Test fun failureStillStopsTheAdvertAndClosesTheTunnel() {
        val tunnel = FakeTunnel(emptyList()) // the computer never sends anything
        val ble = FakeBle()
        val e = runCatching { HybridTransport(ble, tunnel).authenticate(qr) { error("no request, no choice") } }.exceptionOrNull()
        assertTrue("a SignInFailure with a message for the user", e is HybridTransport.SignInFailure)
        assertEquals("The computer ended the sign-in.", e!!.message)
        assertEquals(1, ble.started)
        assertEquals(1, ble.stopped)
        assertTrue(tunnel.closed >= 1)
    }

    @Test fun cancelBeforeConnectingFinishesClosesTheTunnel() {
        val tunnel = FakeTunnel(listOf(getAssertion()))
        val ble = FakeBle()
        val transport = HybridTransport(ble, tunnel)
        transport.cancel() // the user closed the screen while the tunnel was still opening
        val e = runCatching { transport.authenticate(qr) { CtapAuthenticator.Decision.Denied } }.exceptionOrNull()
        assertTrue(e is HybridTransport.SignInFailure)
        assertEquals(0, ble.started) // nothing broadcast
        assertTrue(tunnel.closed >= 1)
    }

    /** [FakeTunnel], but hosts in [unreachable] fail as if the server were down. */
    private class PartlyReachable(requests: List<ByteArray>, val unreachable: Set<String>) : HybridTransport.TunnelClient {
        val inner = FakeTunnel(requests)
        val urls = mutableListOf<String>()
        override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel {
            urls += tunnelUrl
            if (java.net.URI(tunnelUrl).host in unreachable) throw HybridTransport.SignInFailure("Could not reach ${java.net.URI(tunnelUrl).host}.")
            return inner.connectNewTunnel(tunnelUrl)
        }
    }

    @Test fun fallsBackToTheSecondServer() {
        val own = TunnelDomains.hostname(266)!!
        val tunnel = PartlyReachable(listOf(getAssertion()), unreachable = setOf(own))
        val transport = HybridTransport(FakeBle(), tunnel, listOf(266, TunnelDomains.GOOGLE))
        transport.authenticate(qr) { CtapAuthenticator.Decision.NoCredentials }
        assertEquals(listOf("cable.wufkweyy3uaxb.com", "cable.ua5v.com"), tunnel.urls.map { java.net.URI(it).host })
        assertTrue(tunnel.urls.all { it.matches(Regex("wss://[a-z0-9.]+/cable/new/[0-9a-f]{32}")) })
        assertEquals("cable.ua5v.com", transport.usedHost)
    }

    @Test fun bothServersUnreachableNamesBoth() {
        val tunnel = PartlyReachable(listOf(getAssertion()), unreachable = setOf("cable.wufkweyy3uaxb.com", "cable.ua5v.com"))
        val e = runCatching {
            HybridTransport(FakeBle(), tunnel, listOf(266, TunnelDomains.GOOGLE)).authenticate(qr) { CtapAuthenticator.Decision.Denied }
        }.exceptionOrNull()
        assertTrue(e is HybridTransport.SignInFailure)
        assertTrue(e!!.message!!.contains("cable.wufkweyy3uaxb.com or cable.ua5v.com"))
    }

    @Test fun eidCarriesTheServerNumberLittleEndian() {
        val transport = HybridTransport(FakeBle(), FakeTunnel(emptyList()))
        val eid = transport.buildEidPlaintext(byteArrayOf(1, 2, 3), 266) // 0x010A
        assertEquals(0x0A.toByte(), eid[14])
        assertEquals(0x01.toByte(), eid[15])
        assertEquals(0.toByte(), transport.buildEidPlaintext(byteArrayOf(1, 2, 3))[14]) // Google: 0
    }
}
