package it.snel.passkeychain.update

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.content.FileProvider
import it.snel.passkeychain.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import it.snel.passkeychain.util.Dbg
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
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
        /** debug only: CI is still building [build], newer than this app; nothing to install yet */
        data class Building(val build: Long) : Status
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
            when {
                isNewer(latest) -> Status.Available(latest)
                BuildConfig.DEBUG -> buildInProgress()?.let { Status.Building(it) } ?: Status.UpToDate
                else -> Status.UpToDate
            }
        } catch (e: IOException) {
            Status.Error(e.message ?: "Network error")
        }
    }

    private fun isNewer(r: Release): Boolean =
        if (r.build != null) r.build > currentBuild else Versions.isNewer(r.version, currentVersion)

    private fun latestDebug(): Release {
        // CI replaces the JSON with --clobber (delete, then upload): for a
        // moment it is missing, so a 404 is tried again before believing it
        val r = fetch("$REPO/releases/download/$DEBUG_TAG/passkeychain-debug.json", retry404 = true,
            headers = mapOf("Cache-Control" to "no-cache"))
        val body = when {
            r.code in 200..299 -> r.body ?: ""
            r.code == 404 -> throw IOException("No debug build has been published yet")
            transient(r.code) -> throw IOException(gitHubTrouble(r.code))
            else -> throw IOException("Unexpected answer from GitHub (HTTP ${r.code})")
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

    /**
     * The run number of a CI build of main that has not finished yet and is
     * newer than this app, or null. Best effort through the public API (60
     * requests an hour without a token); any failure just means "no".
     */
    private fun buildInProgress(): Long? {
        return try {
            val r = fetch("$API/actions/runs?branch=main&event=push&per_page=5", attempts = 1,
                headers = mapOf("Accept" to "application/vnd.github+json"))
            if (r.code !in 200..299) return null
            val runs = JSONObject(r.body ?: return null).getJSONArray("workflow_runs")
            (0 until runs.length()).map { runs.getJSONObject(it) }
                .filter { it.optString("status") != "completed" }
                .map { it.getLong("run_number") }
                .filter { it > currentBuild }
                .maxOrNull()
        } catch (e: IOException) {
            null
        } catch (e: JSONException) {
            null
        }
    }

    private fun latestRelease(): Release {
        val r = fetch("$REPO/releases/latest", followRedirects = false)
        if (transient(r.code)) throw IOException(gitHubTrouble(r.code))
        val code = r.code
        val location = r.location
        val tag = location?.let { Regex("/releases/tag/([^/?#]+)").find(it)?.groupValues?.get(1) }
            ?.let { URLDecoder.decode(it, "UTF-8") }
            ?: throw IOException(
                if (code in 300..399) "No version has been published yet" else "Unexpected answer from GitHub (HTTP $code)"
            )
        return Release(tag, tag.removePrefix("v"), "$REPO/releases/download/$tag/passkeychain-$tag.apk")
    }

    /** Whether Android lets this app start the package installer ("Install unknown apps"). */
    fun canInstall(): Boolean = context.packageManager.canRequestPackageInstalls()

    /** The settings screen where the user allows this app to install updates. */
    fun installPermissionIntent(): Intent =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))

    /**
     * Downloads the APK of [release] to the cache and checks it: complete,
     * this app, and newer than the installed version. Does not install.
     */
    suspend fun download(release: Release, onProgress: (Int) -> Unit = {}): File = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "updates").apply { deleteRecursively(); mkdirs() }
        val out = File(dir, "passkeychain-${release.tag}.apk")
        val response = call(release.apkUrl)
        response.use { resp ->
            if (transient(resp.code)) throw IOException(gitHubTrouble(resp.code))
            if (resp.code !in 200..299) throw IOException("Download failed (HTTP ${resp.code})")
            val body = resp.body ?: throw IOException("Download failed (empty answer)")
            val total = body.contentLength()
            var done = 0L
            body.byteStream().use { ins ->
                out.outputStream().use { os ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = ins.read(buf)
                        if (n < 0) break
                        os.write(buf, 0, n)
                        done += n
                        if (total > 0) onProgress((done * 100 / total).toInt())
                    }
                }
            }
            if (total > 0 && done != total) throw IOException("The download was incomplete. Try again.")
        }
        // Android refuses another signature or package itself; this catches a
        // broken, wrong or stale file early, with a clear message
        val pi = context.packageManager.getPackageArchiveInfo(out.path, 0)
        when {
            pi == null || pi.packageName != context.packageName -> {
                out.delete()
                throw IOException("The downloaded file is not a PassKeyChain app")
            }
            pi.longVersionCode <= currentBuild -> {
                out.delete()
                throw IOException("The downloaded file is not newer than this version. Try again in a minute.")
            }
        }
        out
    }

    /** Opens the system package installer for [apk]. Call it while the app is in the foreground. */
    fun install(apk: File) {
        val uri: Uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", apk)
        context.startActivity(Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            // the installer in its own task: in ours it goes down with the old app
            // during the update, and its "Open" then lands in a dying task and does nothing
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        })
    }

    // OkHttp rather than HttpURLConnection: it notices dead pooled connections
    // instead of hanging on them until "timeout"
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    private val noRedirects = client.newBuilder().followRedirects(false).build()

    private class Answer(val code: Int, val body: String?, val location: String?)

    /**
     * GET [url], tried up to [attempts] times while GitHub has trouble: a
     * server error or 429, a timeout or a broken connection (and a 404 when
     * [retry404]). The last answer is returned; if the last try did not get
     * one, the error says why.
     */
    private fun fetch(
        url: String,
        followRedirects: Boolean = true,
        headers: Map<String, String> = emptyMap(),
        retry404: Boolean = false,
        attempts: Int = RETRIES,
    ): Answer {
        var answer: Answer? = null
        var error: IOException? = null
        for (attempt in 1..attempts) {
            try {
                val request = Request.Builder().url(url).header("User-Agent", USER_AGENT)
                    .apply { headers.forEach { (k, v) -> header(k, v) } }.build()
                (if (followRedirects) client else noRedirects).newCall(request).execute().use { r ->
                    Dbg.d(TAG, "GET $url -> HTTP ${r.code} (try $attempt)")
                    answer = Answer(r.code, r.body?.string(), r.header("Location"))
                    error = null
                }
                val code = answer!!.code
                if (!transient(code) && !(retry404 && code == 404)) return answer!!
            } catch (e: IOException) {
                Dbg.w(TAG, "GET $url failed (try $attempt): $e")
                error = e
            }
            if (attempt < attempts) Thread.sleep(backoff(attempt))
        }
        error?.let { throw IOException(unreachable(url, it), it) }
        return answer!!
    }

    /** A streaming GET (for the APK), with the same retries before the answer starts. */
    private fun call(url: String): okhttp3.Response {
        var error: IOException? = null
        for (attempt in 1..RETRIES) {
            try {
                val r = client.newCall(Request.Builder().url(url).header("User-Agent", USER_AGENT).build()).execute()
                Dbg.d(TAG, "GET $url -> HTTP ${r.code} (try $attempt)")
                if (!transient(r.code) || attempt == RETRIES) return r
                r.close()
            } catch (e: IOException) {
                Dbg.w(TAG, "GET $url failed (try $attempt): $e")
                error = e
            }
            if (attempt < RETRIES) Thread.sleep(backoff(attempt))
        }
        throw IOException(unreachable(url, error!!), error)
    }

    private fun unreachable(url: String, e: IOException): String {
        val host = runCatching { java.net.URI(url).host }.getOrDefault("GitHub")
        return when (e) {
            is java.net.SocketTimeoutException -> "$host didn't answer in time (tried $RETRIES times). Check the connection, or try again in a few minutes."
            is java.net.UnknownHostException -> "Can't find $host: is the phone online?"
            else -> "Could not reach $host: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    companion object {
        private const val TAG = "UpdateChecker"
        private const val USER_AGENT = "PassKeyChain-Updater"
        private const val RETRIES = 4

        /** GitHub's own trouble, worth trying again: a server error (502, 503, 504, …) or "too many requests". */
        fun transient(code: Int) = code == 429 || code in 500..599

        /** 2, 4, 8 seconds. */
        private fun backoff(attempt: Int) = 2_000L shl (attempt - 1)

        fun gitHubTrouble(code: Int) =
            "GitHub isn't answering properly right now (HTTP $code, a problem on GitHub's side). Try again in a few minutes."

        const val REPO = "https://github.com/rsnel/passkeychain"
        const val DEBUG_TAG = "debug"
        private const val API = "https://api.github.com/repos/rsnel/passkeychain"
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
