package it.snel.passkeychain.store

import android.content.Context
import it.snel.passkeychain.io.Bitwarden
import it.snel.passkeychain.io.OkHttpVault
import it.snel.passkeychain.io.VaultSync
import it.snel.passkeychain.model.HistoryEntry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.Base64

/**
 * Live sync with a Bitwarden-compatible server, without the master password:
 * it keeps the server's refresh token and the vault key, both encrypted with
 * the Android Keystore (as the passkeys are). It runs when the app comes to
 * the front (at most every few minutes), after a passkey is created, and on
 * request. Each run:
 *
 *  - pull: adds passkeys that are new in the vault since the last run. One you
 *    deleted on the phone is not brought back, and nothing is overwritten;
 *  - push: adds passkeys created on this phone that have no copy anywhere yet
 *    (not backed up) to the vault, as new items: in the account's own vault,
 *    or in a chosen organisation collection (to share them with another
 *    account, such as a main account, while this one holds only passkeys).
 *
 * Nothing is deleted on either side.
 */
object LiveSync {
    enum class Light { Off, Ok, Warning, Offline }

    class Status(
        val light: Light,
        val message: String,
        val time: Long = System.currentTimeMillis(),
        val stats: Map<String, String> = emptyMap(),
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private val _status = MutableStateFlow(Status(Light.Off, "Not set up"))
    val status: StateFlow<Status> = _status
    private val _running = MutableStateFlow(false)
    /** Whether a sync is running now (for the pull-to-refresh indicator). */
    val running: StateFlow<Boolean> = _running
    private const val MIN_INTERVAL_MS = 5 * 60_000L

    private fun prefs(ctx: Context) = ctx.applicationContext.getSharedPreferences("live_sync", Context.MODE_PRIVATE)

    fun isOn(ctx: Context) = prefs(ctx).getBoolean("on", false)

    /** Loads the last known status (for the indicator after a restart). */
    fun init(ctx: Context) {
        val p = prefs(ctx)
        if (!p.getBoolean("on", false)) { _status.value = Status(Light.Off, "Not set up"); return }
        val light = runCatching { Light.valueOf(p.getString("light", "Ok")!!) }.getOrDefault(Light.Ok)
        val stats = runCatching { JSONObject(p.getString("stats", "{}")!!).let { o -> o.keys().asSequence().associateWith { o.getString(it) } } }
            .getOrDefault(emptyMap())
        _status.value = Status(light, p.getString("message", "") ?: "", p.getLong("time", 0), stats)
    }

    /** Turns live sync on with a freshly opened session (after sign-in with the master password). */
    fun enable(ctx: Context, server: String, email: String, session: VaultSync.Session) {
        prefs(ctx).edit()
            .putBoolean("on", true)
            .putString("server", server)
            .putString("email", email)
            .putString("key", seal(session.vaultKey))
            .putString("token", session.refreshToken?.let { seal(it.toByteArray()) })
            .putString("known", "[]")
            .apply()
        kick(ctx, force = true)
    }

    /** Turns it off and deletes the stored vault key and token. */
    fun disable(ctx: Context) {
        prefs(ctx).edit().clear().apply()
        _status.value = Status(Light.Off, "Not set up")
    }

    /** Runs a sync in the background, unless one ran recently ([force] ignores that). Whether it started one. */
    fun kick(ctx: Context, force: Boolean = false): Boolean {
        val app = ctx.applicationContext
        if (!isOn(app)) return false
        if (!force && System.currentTimeMillis() - prefs(app).getLong("time", 0) < MIN_INTERVAL_MS) return false
        _running.value = true
        scope.launch {
            try { run(app) } finally { _running.value = lock.isLocked }
        }
        return true
    }

    private suspend fun run(ctx: Context) = lock.withLock {
        val p = prefs(ctx)
        if (!p.getBoolean("on", false)) return@withLock
        val server = p.getString("server", "")!!
        val host = runCatching { java.net.URI(server).host }.getOrDefault(server)
        val stats = linkedMapOf("Server" to host, "Account" to (p.getString("email", "") ?: ""))
        val started = System.currentTimeMillis()
        val result: Status = try {
            val token = p.getString("token", null)?.let { String(unseal(it)) } ?: throw VaultSync.NeedsSignIn("No sign-in saved.")
            val key = unseal(p.getString("key", null) ?: throw VaultSync.NeedsSignIn("No vault key saved."))
            val vault = VaultSync(server, OkHttpVault(), VaultSettings(ctx).deviceId)
            vault.serverInfo()?.let { stats["Software"] = it }
            val session = vault.openWithKey(token, key)
            session.refreshToken?.let { p.edit().putString("token", seal(it.toByteArray())).apply() }

            val collections = vault.collections(session)
            p.edit().putString("collections", JSONArray(collections.map {
                JSONObject().put("orgId", it.orgId).put("orgName", it.orgName).put("id", it.id).put("name", it.name)
            }).toString()).apply()
            val targetId = p.getString("target", null)
            val target = targetId?.let { id -> collections.firstOrNull { it.id == id } }
            if (targetId != null && target == null) throw VaultSync.Failure("The chosen collection is gone; choose where new passkeys go.")
            stats["New passkeys go to"] = target?.label ?: "this account's vault"

            val inVault = vault.passkeys(session)
            val remote = Bitwarden.parse(inVault.exportJson).imported
            if (remote.isEmpty() && inVault.skipped.isNotEmpty())
                throw VaultSync.NeedsSignIn("The vault key no longer opens the vault (was it rotated?).")
            val remoteIds = remote.map { it.credentialId }.toSet()
            val known = JSONArray(p.getString("known", "[]")).let { a -> (0 until a.length()).map { a.getString(it) }.toSet() }

            val store = PasskeyStore(ctx)
            val history = SignInHistory(ctx)
            val local = store.load()
            val localIds = local.map { it.credentialId }.toSet()
            // pull: new in the vault since the last run, and not on the phone
            val pulled = remote.filter { it.credentialId !in known && it.credentialId !in localIds }
            // push: created here, no copy anywhere yet, not in the vault
            val toPush = local.filter { !it.backedUp && it.credentialId !in remoteIds }
            val pushed = if (toPush.isEmpty()) emptyList() else vault.upload(session, toPush, into = target).also { up ->
                if (up.failed.isNotEmpty()) stats["Last upload problem"] = up.failed.first()
            }.added
            if (pulled.isNotEmpty() || pushed.isNotEmpty()) {
                val pushedIds = pushed.map { it.credentialId }.toSet()
                store.save(store.load().map { if (it.credentialId in pushedIds) it.copy(backedUp = true) else it } + pulled)
                if (pulled.isNotEmpty()) history.add(HistoryEntry.change(HistoryEntry.Outcome.Imported, account = "from $host (live sync)",
                    detail = count(pulled.size) + " new in the vault"))
                if (pushed.isNotEmpty()) history.add(HistoryEntry.change(HistoryEntry.Outcome.Exported, account = "to $host (live sync)",
                    detail = count(pushed.size) + " added to the vault"))
            }
            p.edit().putString("known", JSONArray(remoteIds + pushed.map { it.credentialId }).toString()).apply()

            stats["Passkeys in the vault"] = (remote.size + pushed.size).toString()
            stats["Last run"] = "${pulled.size} in, ${pushed.size} out"
            stats["Response time"] = "${System.currentTimeMillis() - started} ms"
            when {
                inVault.skipped.isNotEmpty() -> Status(Light.Warning, "${inVault.skipped.size} vault item(s) could not be decrypted.", stats = stats)
                toPush.size > pushed.size -> Status(Light.Warning, "${toPush.size - pushed.size} passkey(s) could not be added to the vault.", stats = stats)
                else -> Status(Light.Ok, "In sync.", stats = stats)
            }
        } catch (e: VaultSync.NeedsSignIn) {
            Status(Light.Warning, e.message ?: "Sign in again.", stats = stats + ("Needs" to "sign in again"))
        } catch (e: VaultSync.Failure) {
            if (e.cause is IOException) Status(Light.Offline, e.message ?: "No connection.", stats = stats)
            else Status(Light.Warning, e.message ?: "Unexpected answer from the server.", stats = stats)
        } catch (e: IOException) {
            Status(Light.Offline, "No connection: ${e.message}", stats = stats)
        } catch (e: Exception) {
            Status(Light.Warning, "Unexpected: ${e.message ?: e.javaClass.simpleName}", stats = stats)
        }
        if (result.light == Light.Ok) p.edit().putLong("last_ok", result.time).apply()
        val lastOk = p.getLong("last_ok", 0)
        val withTimes = result.stats + ("Last success" to if (lastOk > 0) java.text.DateFormat.getDateTimeInstance().format(lastOk) else "never")
        val final = Status(result.light, result.message, result.time, withTimes)
        p.edit()
            .putString("light", final.light.name)
            .putString("message", final.message)
            .putLong("time", final.time)
            .putString("stats", JSONObject(final.stats).toString())
            .apply()
        _status.value = final
    }

    /** The organisation collections seen at the last run, for choosing where new passkeys go. */
    fun collections(ctx: Context): List<VaultSync.Collection> = runCatching {
        val a = JSONArray(prefs(ctx).getString("collections", "[]"))
        (0 until a.length()).map { a.getJSONObject(it) }.map {
            VaultSync.Collection(it.getString("orgId"), it.getString("orgName"), it.getString("id"), it.getString("name"))
        }
    }.getOrDefault(emptyList())

    /** Where new passkeys go: a collection, or null for the account's own vault. */
    fun target(ctx: Context): VaultSync.Collection? {
        val id = prefs(ctx).getString("target", null) ?: return null
        return collections(ctx).firstOrNull { it.id == id }
    }

    fun setTarget(ctx: Context, c: VaultSync.Collection?) {
        prefs(ctx).edit().apply { if (c == null) remove("target") else putString("target", c.id) }.apply()
        _status.value = _status.value.let { Status(it.light, it.message, it.time, it.stats + ("New passkeys go to" to (c?.label ?: "this account's vault"))) }
    }

    private fun count(n: Int) = if (n == 1) "1 passkey" else "$n passkeys"

    private fun seal(b: ByteArray) = Base64.getEncoder().encodeToString(KeystoreCrypto.encrypt(b))
    private fun unseal(s: String) = KeystoreCrypto.decrypt(Base64.getDecoder().decode(s))
}
