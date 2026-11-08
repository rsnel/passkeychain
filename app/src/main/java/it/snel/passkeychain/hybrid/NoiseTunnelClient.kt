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
 * [onBrowserConnected] is called when the computer's first handshake message
 * arrives, [onHandshakeDone] once the handshake has completed (progress
 * display, and the Bluetooth advert can stop: the browser has found us).
 */
class NoiseTunnelClient(
    /** the computer has found the phone and sent the first handshake message */
    private val onBrowserConnected: () -> Unit = {},
    private val onHandshakeDone: () -> Unit = {},
) : HybridTransport.TunnelClient {

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
            // Before the computer has connected, the tunnel server only waits for it:
            // when it gives up and closes (or the wait breaks off), the cause is
            // nearly always that the computer never saw the Bluetooth broadcast.
            val waitingForComputer = crypter == null
            return when (event) {
                is Event.Data -> event.bytes
                is Event.Closed -> throw SignInFailure(
                    if (waitingForComputer) NO_COMPUTER else "The computer ended the sign-in.",
                )
                is Event.Broken -> {
                    incoming.offer(event) // later waits end at once too
                    throw SignInFailure(
                        when {
                            event.cause == null -> "Cancelled."
                            waitingForComputer -> "$NO_COMPUTER If that doesn't help, check the phone's internet connection."
                            else -> "The connection to the tunnel server was lost. Check the phone's internet connection."
                        },
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
                when (val m = TunnelMessages.classify(pt)) {
                    is TunnelMessages.Incoming.Ctap -> {
                        Dbg.d(TAG, "receive(): CTAP2 command 0x%02x".format(m.command[0]))
                        return m.command
                    }
                    TunnelMessages.Incoming.Shutdown -> {
                        Dbg.w(TAG, "receive(): kShutdown from Chrome")
                        throw SignInFailure("The sign-in was cancelled on the computer.")
                    }
                    is TunnelMessages.Incoming.Ignore -> Dbg.d(TAG, "receive(): ignoring: ${m.why}")
                }
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
            val msg1 = next(MSG1_TIMEOUT, NO_COMPUTER)
            onBrowserConnected()
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
        /** The computer never connected: it did not pick up the Bluetooth broadcast. */
        const val NO_COMPUTER = "Your computer did not respond: it didn't pick up the phone's Bluetooth broadcast. " +
            "Move the phone close to the computer, check that Bluetooth is on on the computer, and scan a fresh QR code."

        /** how long the computer gets to find the Bluetooth broadcast and connect */
        const val MSG1_TIMEOUT = 90L
        /** how long the computer gets to send its request after the handshake */
        const val REQUEST_TIMEOUT = 60L
    }
}
