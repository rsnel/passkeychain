package it.snel.passkeychain.update

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import it.snel.passkeychain.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * In-app updater. The app only ever looks at its own channel:
 *   - debug builds   -> pre-releases tagged `debug-v<name>+<code>`
 *   - release builds -> final releases tagged `v<name>+<code>`
 *
 * so a debug install never tries to replace itself with a release-signed APK
 * (which Android would reject for a different signature anyway) and vice-versa.
 */
class UpdateChecker(private val context: Context) {

    private val repo = BuildConfig.UPDATE_REPO
    private val channel = BuildConfig.UPDATE_CHANNEL
    private val tagPrefix = if (channel == "debug") "debug-v" else "v"

    data class Release(val tag: String, val versionCode: Long, val apkUrl: String?, val notes: String)

    sealed interface Status {
        data object UpToDate : Status
        data class Available(val release: Release) : Status
        data class Error(val message: String) : Status
    }

    private fun currentVersionCode(): Long =
        context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode

    suspend fun check(): Status = withContext(Dispatchers.IO) {
        runCatching {
            val releases = fetchReleases()
            val newest = releases
                .filter { it.tag.startsWith(tagPrefix) }
                .maxByOrNull { it.versionCode }
                ?: return@runCatching Status.UpToDate
            if (newest.versionCode > currentVersionCode()) Status.Available(newest) else Status.UpToDate
        }.getOrElse { Status.Error(it.message ?: it.javaClass.simpleName) }
    }

    private fun fetchReleases(): List<Release> {
        val url = URL("https://api.github.com/repos/$repo/releases?per_page=30")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "PassKeyChain-Updater")
            connectTimeout = 15000; readTimeout = 15000
        }
        conn.inputStream.use { ins ->
            val arr = JSONArray(ins.readBytes().toString(Charsets.UTF_8))
            return (0 until arr.length()).mapNotNull { parseRelease(arr.getJSONObject(it)) }
        }
    }

    private fun parseRelease(o: JSONObject): Release? {
        val tag = o.optString("tag_name").ifBlank { return null }
        val code = tag.substringAfter('+', "").toLongOrNull() ?: return null
        val assets = o.optJSONArray("assets") ?: JSONArray()
        val apk = (0 until assets.length())
            .map { assets.getJSONObject(it) }
            .firstOrNull { it.optString("name").endsWith(".apk") }
            ?.optString("browser_download_url")
        return Release(tag, code, apk, o.optString("body"))
    }

    /** Downloads the APK to cache and launches the system package installer. */
    suspend fun downloadAndInstall(release: Release, onProgress: (Int) -> Unit = {}) {
        val apkUrl = release.apkUrl ?: throw IllegalStateException("release has no APK asset")
        val apk = withContext(Dispatchers.IO) {
            val out = File(context.cacheDir, "update-${release.tag}.apk")
            val conn = (URL(apkUrl).openConnection() as HttpURLConnection).apply {
                setRequestProperty("User-Agent", "PassKeyChain-Updater")
                instanceFollowRedirects = true
                connectTimeout = 15000; readTimeout = 60000
            }
            val total = conn.contentLengthLong.coerceAtLeast(1)
            conn.inputStream.use { ins ->
                out.outputStream().use { os ->
                    val buf = ByteArray(64 * 1024); var read = 0L; var n: Int
                    while (ins.read(buf).also { n = it } >= 0) {
                        os.write(buf, 0, n); read += n
                        onProgress(((read * 100) / total).toInt().coerceIn(0, 100))
                    }
                }
            }
            out
        }
        val uri: Uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", apk)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }
}
