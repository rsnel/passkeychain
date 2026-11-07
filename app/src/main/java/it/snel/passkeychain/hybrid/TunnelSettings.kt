package it.snel.passkeychain.hybrid

import android.content.Context

/** Which tunnel servers to use: a first choice, and one to try when that is unreachable. */
class TunnelSettings(context: Context) {
    private val prefs = context.getSharedPreferences("tunnel_server", Context.MODE_PRIVATE)

    var first: Int
        get() = prefs.getInt("first", TunnelDomains.GOOGLE).takeIf { TunnelDomains.hostname(it) != null } ?: TunnelDomains.GOOGLE
        set(value) { prefs.edit().putInt("first", value).apply() }

    var second: Int
        get() = prefs.getInt("second", TunnelDomains.NONE).takeIf { it == TunnelDomains.NONE || TunnelDomains.hostname(it) != null }
            ?: TunnelDomains.NONE
        set(value) { prefs.edit().putInt("second", value).apply() }

    /** The servers to try, in order. */
    fun order(): List<Int> = listOf(first, second).filter { it != TunnelDomains.NONE }.distinct()
}
