package it.snel.passkeychain.update

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import it.snel.passkeychain.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLDecoder

/**
 * Finds and installs new versions from GitHub, the same way Kaartscan does.
 *
 * The debug app follows the pre-release 'debug', which CI replaces on every
 * push to main with passkeychain-debug.apk and passkeychain-debug.json
 * ({"version", "build", "commit"}); "build" is the CI run number, which is
 * also the APK's versionCode.
 *
 * The release app follows the releases CI creates for v* tags
 * (passkeychain-<tag>.apk). The latest one is found through the redirect of
 * /releases/latest, not the GitHub API with its 60 requests/hour limit. A
 * pre-release is never 'latest', so release apps never see debug builds.
 */
class UpdateChecker(private val context: Context) {

    /** [build] is set for debug builds (the CI run number), null for releases. */
    data class Release(val tag: String, val version: String, val apkUrl: String, val build: Long? = null) {
        val label: String get() = if (build != null) "$version (build $build)" else version
    }

    sealed interface Status {
        data object UpToDate : Status
        data class Available(val release: Release) : Status
        data class Error(val message: String) : Status
    }

    private val info = context.packageManager.getPackageInfo(context.packageName, 0)
    val currentVersion: String = info.versionName ?: "dev"
    val currentBuild: Long = info.longVersionCode

    /** "1.0" for the release app, "1.0-5-gabc1234 (build 57)" for the debug app */
    val currentLabel: String = if (BuildConfig.DEBUG) "$currentVersion (build $currentBuild)" else currentVersion

    suspend fun check(): Status = withContext(Dispatchers.IO) {
        try {
            val latest = if (BuildConfig.DEBUG) latestDebug() else latestRelease()
            if (isNewer(latest)) Status.Available(latest) else Status.UpToDate
        } catch (e: IOException) {
            Status.Error(e.message ?: "Network error")
        }
    }

    private fun isNewer(r: Release): Boolean =
        if (r.build != null) r.build > currentBuild else Versions.isNewer(r.version, currentVersion)

    private fun latestDebug(): Release {
        val conn = open("$REPO/releases/download/$DEBUG_TAG/passkeychain-debug.json")
        conn.setRequestProperty("Cache-Control", "no-cache")
        val body = try {
            if (conn.responseCode == 404) throw IOException("No debug build has been published yet")
            if (conn.responseCode !in 200..299) throw IOException("Unexpected answer from GitHub (HTTP ${conn.responseCode})")
            conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
        } finally {
            conn.disconnect()
        }
        return try {
            val o = JSONObject(body)
            Release(
                tag = DEBUG_TAG,
                version = o.getString("version"),
                apkUrl = "$REPO/releases/download/$DEBUG_TAG/passkeychain-debug.apk",
                build = o.getLong("build"),
            )
        } catch (e: JSONException) {
            throw IOException("Invalid debug build information")
        }
    }

    private fun latestRelease(): Release {
        val conn = open("$REPO/releases/latest").apply { instanceFollowRedirects = false }
        val (code, location) = try {
            conn.responseCode to conn.getHeaderField("Location")
        } finally {
            conn.disconnect()
        }
        val tag = location?.let { Regex("/releases/tag/([^/?#]+)").find(it)?.groupValues?.get(1) }
            ?.let { URLDecoder.decode(it, "UTF-8") }
            ?: throw IOException(
                if (code in 300..399) "No version has been published yet" else "Unexpected answer from GitHub (HTTP $code)"
            )
        return Release(tag, tag.removePrefix("v"), "$REPO/releases/download/$tag/passkeychain-$tag.apk")
    }

    /** Downloads the APK to the cache and launches the system package installer. */
    suspend fun downloadAndInstall(release: Release, onProgress: (Int) -> Unit = {}) {
        val apk = withContext(Dispatchers.IO) {
            val dir = File(context.cacheDir, "updates").apply { deleteRecursively(); mkdirs() }
            val out = File(dir, "passkeychain-${release.tag}.apk")
            val conn = open(release.apkUrl)
            try {
                if (conn.responseCode !in 200..299) throw IOException("Download failed (HTTP ${conn.responseCode})")
                val total = conn.contentLengthLong
                conn.inputStream.use { ins ->
                    out.outputStream().use { os ->
                        val buf = ByteArray(64 * 1024)
                        var done = 0L
                        while (true) {
                            val n = ins.read(buf)
                            if (n < 0) break
                            os.write(buf, 0, n)
                            done += n
                            if (total > 0) onProgress((done * 100 / total).toInt())
                        }
                    }
                }
            } finally {
                conn.disconnect()
            }
            // Android refuses another signature or package itself; this only
            // catches a broken or wrong file early
            val pi = context.packageManager.getPackageArchiveInfo(out.path, 0)
            if (pi == null || pi.packageName != context.packageName) {
                out.delete()
                throw IOException("The downloaded file is not a PassKeyChain app")
            }
            out
        }
        val uri: Uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", apk)
        context.startActivity(Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        })
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            setRequestProperty("User-Agent", "PassKeyChain-Updater")
            connectTimeout = 15_000
            readTimeout = 60_000
        }

    companion object {
        const val REPO = "https://github.com/rsnel/passkeychain"
        const val DEBUG_TAG = "debug"
    }
}

/** Version names as git describe makes them: "1.10", "1.9-3-gabc1234", "1.9-dirty". */
object Versions {
    private val pattern = Regex("^v?(\\d+(?:\\.\\d+)+)(-\\d+-g[0-9a-f]+)?(-dirty)?$")

    private fun parts(version: String): List<Int>? =
        pattern.find(version.trim())?.groupValues?.get(1)?.split('.')?.map { it.toInt() }

    /** true when [remote] is newer than [current]; an unrecognisable [current] (a dev build) counts as older. */
    fun isNewer(remote: String, current: String): Boolean {
        val r = parts(remote) ?: return false
        val c = parts(current) ?: return true
        for (i in 0 until maxOf(r.size, c.size)) {
            val a = r.getOrElse(i) { 0 }
            val b = c.getOrElse(i) { 0 }
            if (a != b) return a > b
        }
        return false
    }
}
