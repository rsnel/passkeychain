package it.snel.passkeychain.hybrid

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class NoiseTunnelClient : HybridTransport.TunnelClient {
    private val TAG = "NoiseTunnelClient"

    override fun connectNewTunnel(tunnelUrl: String): HybridTransport.TunnelClient.NewTunnel {
        Log.d(TAG, "Connecting to $tunnelUrl")
        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
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
                    Log.d(TAG, "WebSocket open, headers:")
                    response.headers.forEach { (name, value) -> Log.d(TAG, "  $name: $value") }
                    headersRef.set(response.headers)
                    ready.offer(true)
                }
                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                    incoming.offer(bytes.toByteArray())
                }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    Log.e(TAG, "WebSocket failure: ${t.message}", t)
                    response?.headers?.forEach { (name, value) -> Log.e(TAG, "  resp $name: $value") }
                    ready.offer(false)
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    Log.d(TAG, "WebSocket closed: $code $reason")
                }
            }
        )

        val opened = ready.poll(15, TimeUnit.SECONDS) ?: false
        if (!opened) throw HybridTransport.DeviceStageMissing("WebSocket did not open")

        val headers = headersRef.get() ?: throw HybridTransport.DeviceStageMissing("no response headers")
        val shardHeader = headers["X-caBLE-Shard"]
            ?: throw HybridTransport.DeviceStageMissing("X-caBLE-Shard header missing")
        Log.d(TAG, "X-caBLE-Shard = $shardHeader")
        val routingId = hexToBytes(shardHeader)
        require(routingId.size == 3) { "routing ID must be 3 bytes, got ${routingId.size}" }

        val channel = buildNoiseChannel(ws, incoming)
        return object : HybridTransport.TunnelClient.NewTunnel {
            override val routingId: ByteArray = routingId
            override val channel: HybridTransport.TunnelClient.Channel = channel
        }
    }

    private fun buildNoiseChannel(ws: WebSocket, incoming: LinkedBlockingQueue<ByteArray>): HybridTransport.TunnelClient.Channel {
        // Placeholder: the real NKpsk0 handshake must be implemented here.
        // For now, return a channel that logs and fails loudly so the next run
        // tells us whether /cable/new/ + X-caBLE-Shard + fido.cable work.
        throw HybridTransport.DeviceStageMissing("Noise NKpsk0 handshake not implemented yet (WebSocket + routing ID succeeded)")
    }

    private fun hexToBytes(s: String): ByteArray {
        val clean = s.replace("-", "")
        require(clean.length % 2 == 0) { "odd hex length" }
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) or Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
    }
}
