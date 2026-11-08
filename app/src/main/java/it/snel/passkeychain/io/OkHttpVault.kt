package it.snel.passkeychain.io

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/** [VaultSync.Http] over OkHttp; network trouble becomes a readable [VaultSync.Failure]. */
class OkHttpVault : VaultSync.Http {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS) // a large vault takes a while
        .build()

    override fun post(url: String, contentType: String, body: String, headers: Map<String, String>) =
        call(Request.Builder().url(url).post(body.toRequestBody(contentType.toMediaType())), headers)

    override fun get(url: String, headers: Map<String, String>) = call(Request.Builder().url(url).get(), headers)

    private fun call(b: Request.Builder, headers: Map<String, String>): VaultSync.Http.Response {
        headers.forEach { (k, v) -> b.header(k, v) }
        b.header("Accept", "application/json")
        val request = b.build()
        return try {
            client.newCall(request).execute().use { VaultSync.Http.Response(it.code, it.body?.string().orEmpty()) }
        } catch (e: IOException) {
            throw VaultSync.Failure("Could not reach ${request.url.host}: ${e.message ?: e.javaClass.simpleName}", e)
        }
    }
}
