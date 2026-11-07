package it.snel.passkeychain.hybrid

import it.snel.passkeychain.hybrid.HybridTransport.SignInFailure
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

    /** What the WebSocket delivers to the worker thread. */
    private sealed interface Event {
        class Data(val bytes: ByteArray) : Event
        /** the other side or the server closed the connection */
        class Closed(val code: Int, val reason: String) : Event
        /** the connection broke (network error), or we closed it ourselves */
        class Broken(val cause: Throwable?) : Event
    }

    override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel {
        Dbg.d(TAG, "Connecting to $tunnelUrl")
        val host = java.net.URI(tunnelUrl).host
        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .build()

        val incoming = LinkedBlockingQueue<Event>()
        val opened = LinkedBlockingQueue<Result<Response>>()

        val ws = client.newWebSocket(
            Request.Builder()
                .url(tunnelUrl)
                .header("Sec-WebSocket-Protocol", "fido.cable")
                .build(),
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    Dbg.d(TAG, "WebSocket open, headers:")
                    response.headers.forEach { (n, v) -> Dbg.d(TAG, "  $n: $v") }
                    opened.offer(Result.success(response))
                }
                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                    val arr = bytes.toByteArray()
                    Dbg.d(TAG, "WS recv ${arr.size} bytes: ${hex(arr)}")
                    incoming.offer(Event.Data(arr))
                }
                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    Dbg.d(TAG, "WS closing: $code $reason")
                    incoming.offer(Event.Closed(code, reason))
                    webSocket.close(1000, null)
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    Dbg.d(TAG, "WS closed: $code $reason")
                    incoming.offer(Event.Closed(code, reason))
                }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    Dbg.e(TAG, "WebSocket failure: ${t.message} (HTTP ${response?.code})", t)
                    response?.headers?.forEach { (n, v) -> Dbg.e(TAG, "  resp $n: $v") }
                    val failure = if (response != null) {
                        SignInFailure("The tunnel server $host refused the connection (HTTP ${response.code}). Try again later.", t)
                    } else {
                        SignInFailure("Could not reach the tunnel server $host. Check the phone's internet connection.", t)
                    }
                    opened.offer(Result.failure(failure))
                    incoming.offer(Event.Broken(t))
                }
            }
        )

        val response = opened.poll(20, TimeUnit.SECONDS)?.getOrThrow() ?: run {
            ws.cancel()
            throw SignInFailure("The tunnel server $host did not answer. Check the phone's internet connection.")
        }
        val routingHeader = response.headers["X-Cable-Routing-Id"] ?: response.headers["X-caBLE-Shard"]
        val routingId = routingHeader?.replace("-", "")?.let(::hexToBytes)
        Dbg.d(TAG, "routing header = $routingHeader")
        if (routingId == null || routingId.size != 3) {
            ws.cancel()
            throw SignInFailure("The tunnel server $host gave an unexpected answer (no routing ID).")
        }

        // The PSK depends on the advert, which needs this routing ID first,
        // so the Noise channel is opened later, by HybridTransport.
        return object : HybridTransport.TunnelClient.NewTunnel {
            override val routingId: ByteArray = routingId
            override fun open(peerIdentity65: ByteArray, psk: ByteArray): HybridTransport.TunnelClient.Channel =
                NoiseResponderChannel(ws, incoming, NoiseHandshake(peerIdentity65, psk, log = { Dbg.d(TAG, it) }), this::close)
            override fun close() {
                // wake a waiting worker first: closing may also report a failure
                incoming.offer(Event.Broken(null))
                if (!ws.close(1000, null)) ws.cancel()
                client.dispatcher.executorService.shutdown()
            }
        }
    }

    private fun hexToBytes(s: String): ByteArray? {
        if (s.length % 2 != 0 || !s.all { Character.digit(it, 16) >= 0 }) return null
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
        private val incoming: LinkedBlockingQueue<Event>,
        private val handshake: NoiseHandshake,
        private val closeTunnel: () -> Unit,
    ) : HybridTransport.TunnelClient.Channel {

        private var crypter: NoiseCrypter? = null

        /**
         * The next message, or a [SignInFailure] saying why there is none:
         * [timeoutMessage] after [seconds], or the connection ended.
         */
        private fun next(seconds: Long, timeoutMessage: String): ByteArray {
            val event = incoming.poll(seconds, TimeUnit.SECONDS)
                ?: throw SignInFailure(timeoutMessage)
            return when (event) {
                is Event.Data -> event.bytes
                is Event.Closed -> throw SignInFailure(
                    if (crypter == null) "The connection closed before the computer connected. Scan a fresh QR code."
                    else "The computer ended the sign-in.",
                )
                is Event.Broken -> {
                    incoming.offer(event) // later waits end at once too
                    throw SignInFailure(
                        if (event.cause == null) "Cancelled."
                        else "The connection to the tunnel server was lost. Check the phone's internet connection.",
                        event.cause,
                    )
                }
            }
        }

        override fun receive(): ByteArray {
            val crypter = crypter ?: handshake().also { crypter = it; onHandshakeDone() }
            while (true) {
                Dbg.d(TAG, "receive(): waiting for a request from the computer")
                val ciphertext = next(REQUEST_TIMEOUT, "The computer stopped responding. Scan a fresh QR code to try again.")
                Dbg.d(TAG, "receive(): got transport ciphertext ${ciphertext.size} bytes: ${hex(ciphertext)}")
                val pt = try {
                    crypter.decrypt(ciphertext)
                } catch (e: Exception) {
                    throw SignInFailure("Could not read the computer's message. Scan a fresh QR code to try again.", e)
                }
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
                    throw SignInFailure("The sign-in was cancelled on the computer.")
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
            if (!ws.send(okio.ByteString.of(*ct))) throw SignInFailure("The connection to the computer was lost before the answer could be sent.")
        }

        override fun close() = closeTunnel()

        /** msg1 in, msg2 out, then the post-handshake message; returns the transport crypter. */
        private fun handshake(): NoiseCrypter {
            // Nothing arrives until the computer has seen the Bluetooth broadcast.
            val msg1 = next(
                MSG1_TIMEOUT,
                "Your computer did not connect. Move the phone close to the computer, check that Bluetooth " +
                    "is on on the computer, and scan a fresh QR code.",
            )
            val result = try {
                handshake.respond(msg1)
            } catch (e: NoiseHandshake.Failed) {
                Dbg.w(TAG, "handshake failed: ${e.message}")
                throw SignInFailure("The computer's answer did not match this QR code. Scan the QR code again.", e)
            }
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

    private companion object {
        /** how long the computer gets to find the Bluetooth broadcast and connect */
        const val MSG1_TIMEOUT = 90L
        /** how long the computer gets to send its request after the handshake */
        const val REQUEST_TIMEOUT = 60L
    }
}
