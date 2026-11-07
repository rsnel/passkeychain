package it.snel.passkeychain.model

import org.json.JSONArray
import org.json.JSONObject

/**
 * One sign-in attempt, for the history screen and "last used": when, which
 * site and account, where (a computer, by QR code, or this phone itself) and
 * how it ended. [credentialId] and [account] are empty when the attempt ended
 * before a passkey was chosen.
 */
data class HistoryEntry(
    val time: Long,                 // epoch milliseconds
    val rpId: String,
    val account: String = "",
    val credentialId: String = "",
    val via: Via,
    val outcome: Outcome,
    val detail: String = "",        // the error message, for Failed
) {
    enum class Via { Computer, ThisPhone }
    enum class Outcome { SignedIn, Created, Denied, Failed }

    val succeeded: Boolean get() = outcome == Outcome.SignedIn || outcome == Outcome.Created

    fun toJson(): JSONObject = JSONObject().apply {
        put("time", time); put("rpId", rpId); put("account", account); put("credentialId", credentialId)
        put("via", via.name); put("outcome", outcome.name); put("detail", detail)
    }

    companion object {
        /** the history keeps this many entries, newest first */
        const val MAX = 200

        fun fromJson(o: JSONObject) = HistoryEntry(
            time = o.getLong("time"),
            rpId = o.optString("rpId"),
            account = o.optString("account"),
            credentialId = o.optString("credentialId"),
            via = runCatching { Via.valueOf(o.getString("via")) }.getOrDefault(Via.Computer),
            outcome = runCatching { Outcome.valueOf(o.getString("outcome")) }.getOrDefault(Outcome.Failed),
            detail = o.optString("detail"),
        )

        fun encode(list: List<HistoryEntry>): String = JSONArray().apply { list.forEach { put(it.toJson()) } }.toString()

        /** Unreadable entries are skipped, not fatal: the history is a convenience. */
        fun decode(text: String): List<HistoryEntry> {
            val arr = runCatching { JSONArray(text) }.getOrNull() ?: return emptyList()
            return (0 until arr.length()).mapNotNull { i -> runCatching { fromJson(arr.getJSONObject(i)) }.getOrNull() }
        }

        /** [entry] added in front, newest first, at most [MAX] entries. */
        fun add(list: List<HistoryEntry>, entry: HistoryEntry): List<HistoryEntry> =
            (listOf(entry) + list).sortedByDescending { it.time }.take(MAX)

        /** When the passkey ([credentialId], [rpId]) last signed in successfully, or null. */
        fun lastUsed(list: List<HistoryEntry>, credentialId: String, rpId: String): Long? =
            list.filter { it.succeeded && it.credentialId == credentialId && it.rpId == rpId }.maxOfOrNull { it.time }
    }
}
