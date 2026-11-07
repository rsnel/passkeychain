package it.snel.passkeychain.hybrid

import it.snel.passkeychain.util.Dbg
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import it.snel.passkeychain.webauthn.Cbor

/**
 * caBLE v2 tunnel client: the WebSocket to the tunnel server, and the messages
 * on it. The cryptography is in [NoiseHandshake] (msg1/msg2, transport keys)
 * and [NoiseCrypter] (transport records), both pure and unit-tested; see
 * docs/PROTOCOL.md.
 *
 * With Debug logging on, the handshake's intermediate values and the raw
 * messages are logged.
 *
 * [onHandshakeDone] is called once the handshake has completed (progress
 * display, and the Bluetooth advert can stop: the browser has found us).
 */
class NoiseTunnelClient(private val onHandshakeDone: () -> Unit = {}) : HybridTransport.TunnelClient {

    private val TAG = "NoiseTunnelClient"

    override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel {
        Dbg.d(TAG, "Connecting to $tunnelUrl")
        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .build()

        val incoming = LinkedBlockingQueue<ByteArray>()
        val ready = LinkedBlockingQueue<Boolean>()
        val headersRef = java.util.concurrent.atomic.AtomicReference<okhttp3.Headers>()

        val ws = client.newWebSocket(
            Request.Builder()
                .url(tunnelUrl)
                .header("Sec-WebSocket-Protocol", "fido.cable")
                .build(),
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    Dbg.d(TAG, "WebSocket open, headers:")
                    response.headers.forEach { (n, v) -> Dbg.d(TAG, "  $n: $v") }
                    headersRef.set(response.headers)
                    ready.offer(true)
                }
                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                    val arr = bytes.toByteArray()
                    Dbg.d(TAG, "WS recv ${arr.size} bytes: ${hex(arr)}")
                    incoming.offer(arr)
                }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    Dbg.e(TAG, "WebSocket failure: ${t.message}", t)
                    response?.headers?.forEach { (n, v) -> Dbg.e(TAG, "  resp $n: $v") }
                    ready.offer(false)
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    Dbg.d(TAG, "WS closed: $code $reason")
                }
            }
        )

        val opened = ready.poll(15, TimeUnit.SECONDS) ?: false
        if (!opened) throw HybridTransport.DeviceStageMissing("WebSocket did not open")

        val headers = headersRef.get() ?: throw HybridTransport.DeviceStageMissing("no response headers")
        val shardHeader = headers["X-Cable-Routing-Id"]
            ?: headers["X-caBLE-Shard"]
            ?: throw HybridTransport.DeviceStageMissing("routing header missing")
        Dbg.d(TAG, "routing header = $shardHeader")
        val routingId = hexToBytes(shardHeader.replace("-", ""))
        require(routingId.size == 3) { "routing ID must be 3 bytes, got ${routingId.size}" }

        // The PSK depends on the advert, which needs this routing ID first,
        // so the Noise channel is opened later, by HybridTransport.
        return object : HybridTransport.TunnelClient.NewTunnel {
            override val routingId: ByteArray = routingId
            override fun open(peerIdentity65: ByteArray, psk: ByteArray): HybridTransport.TunnelClient.Channel =
                NoiseResponderChannel(ws, incoming, NoiseHandshake(peerIdentity65, psk, log = { Dbg.d(TAG, it) }))
        }
    }

    private fun hexToBytes(s: String): ByteArray {
        require(s.length % 2 == 0)
        return ByteArray(s.length / 2) { i ->
            ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
        }
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /**
     * The tunnel after the routing ID is known. On the first receive() it runs
     * the handshake (msg1 in, msg2 out, see [NoiseHandshake]) and sends the
     * post-handshake message; after that every record goes through [NoiseCrypter].
     */
    private inner class NoiseResponderChannel(
        private val ws: WebSocket,
        private val incoming: LinkedBlockingQueue<ByteArray>,
        private val handshake: NoiseHandshake,
    ) : HybridTransport.TunnelClient.Channel {

        private var crypter: NoiseCrypter? = null

        override fun receive(): ByteArray {
            val crypter = crypter ?: handshake().also { crypter = it; onHandshakeDone() }
            while (true) {
                Dbg.d(TAG, "receive(): waiting up to 120s for transport ciphertext from Chrome")
                val ciphertext = incoming.poll(120, TimeUnit.SECONDS)
                    ?: run {
                        Dbg.w(TAG, "receive(): timeout, no transport ciphertext from Chrome after post-handshake")
                        throw HybridTransport.DeviceStageMissing("timeout waiting for transport ciphertext")
                    }
                Dbg.d(TAG, "receive(): got transport ciphertext ${ciphertext.size} bytes: ${hex(ciphertext)}")
                val pt = crypter.decrypt(ciphertext)
                Dbg.d(TAG, "receive(): decrypted ${pt.size} bytes: ${hex(pt)}")
                if (pt.isEmpty()) {
                    Dbg.w(TAG, "receive(): empty plaintext, continuing")
                    continue
                }
                val first = pt[0].toInt() and 0xFF
                val second = if (pt.size >= 2) pt[1].toInt() and 0xFF else -1
                val secondIsCborMap = second in 0xA0..0xBF
                Dbg.d(TAG, "receive(): first=0x%02x second=0x%02x cborMap=%b size=${pt.size}".format(first, second and 0xFF, secondIsCborMap))

                // kShutdown: 1-byte message 0x02 (MessageType::kShutdown)
                if (pt.size == 1 && first == 0x02) {
                    Dbg.w(TAG, "receive(): kShutdown from Chrome")
                    throw HybridTransport.DeviceStageMissing("Chrome requested shutdown")
                }
                // kUpdate: 1-byte message 0x03
                if (pt.size == 1 && first == 0x03) {
                    Dbg.d(TAG, "receive(): kUpdate, ignoring")
                    continue
                }
                // authenticatorGetInfo has no parameters: a bare 0x04
                if (pt.size == 1 && first == CtapAuthenticator.CMD_GET_INFO) {
                    Dbg.d(TAG, "receive(): bare CTAP2 getInfo")
                    return pt
                }
                // MessageType::kCTAP (0x00) prefix, followed by a CTAP2 command byte
                if (first == 0x00 && pt.size >= 2 && second in 0x01..0x04) {
                    Dbg.d(TAG, "receive(): MessageType=kCTAP prefix, CTAP2 cmd=0x%02x".format(second))
                    return pt.copyOfRange(1, pt.size)
                }
                // Bare CTAP2 command: first byte is 0x01/0x02/0x04 followed by CBOR map.
                // Chrome in some configurations sends CTAP2 requests without the
                // MessageType prefix (observed for kAuthenticatorGetAssertion).
                if (first in 0x01..0x04 && secondIsCborMap) {
                    Dbg.d(TAG, "receive(): bare CTAP2 cmd=0x%02x (no MessageType prefix)".format(first))
                    return pt
                }
                // kJSON prefix with non-CBOR payload: ignore
                if (first == 0x01) {
                    Dbg.d(TAG, "receive(): kJSON prefix, ignoring")
                    continue
                }
                Dbg.w(TAG, "receive(): unrecognized message (first=0x%02x size=${pt.size}), discarding".format(first))
                continue
            }
        }

        override fun send(plaintext: ByteArray) {
            val crypter = crypter ?: throw IllegalStateException("handshake not done")
            // The plaintext already starts with the CTAP2 status byte
            // (0x00 = CTAP2_OK). Chrome expects [status][CBOR] with no
            // MessageType prefix on outgoing responses: adding one produced
            // 'Trailing data bytes are not allowed' from Chrome's CTAP2 parser.
            val ct = crypter.encrypt(plaintext)
            Dbg.d(TAG, "transport send ${ct.size} bytes (plaintext ${plaintext.size}): ${hex(ct)}")
            ws.send(okio.ByteString.of(*ct))
        }

        override fun close() {
            ws.close(1000, "done")
        }

        /** msg1 in, msg2 out, then the post-handshake message; returns the transport crypter. */
        private fun handshake(): NoiseCrypter {
            val msg1 = incoming.poll(120, TimeUnit.SECONDS)
                ?: throw HybridTransport.DeviceStageMissing("timeout waiting for msg1")
            val result = handshake.respond(msg1)
            ws.send(okio.ByteString.of(*result.msg2))
            val crypter = NoiseCrypter(receiveKey = result.receiveKey, sendKey = result.sendKey)

            // Chrome sends the CTAP2 request only after this: our features and
            // getInfo, padded to 512 bytes (v2_authenticator.cc).
            val postHandshakeCbor = Cbor.encode(mapOf<Any, Any>(
                1 to CtapAuthenticator.getInfo(),   // getInfo, as a CBOR byte string
                3 to listOf("ctap"),                // features
            ))
            Dbg.d(TAG, "post-handshake CBOR ${postHandshakeCbor.size} bytes: ${hex(postHandshakeCbor)}")
            val ct = crypter.encrypt(NoiseCrypter.padPostHandshake(postHandshakeCbor))
            Dbg.d(TAG, "post-handshake ciphertext ${ct.size} bytes: ${hex(ct)}")
            ws.send(okio.ByteString.of(*ct))
            return crypter
        }
    }
}
