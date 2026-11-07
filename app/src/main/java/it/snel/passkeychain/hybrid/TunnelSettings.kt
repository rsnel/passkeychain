package it.snel.passkeychain.hybrid

import android.content.Context

/** Which tunnel servers to use: a first choice, and one to try when that is unreachable. */
class TunnelSettings(context: Context) {
    private val prefs = context.getSharedPreferences("tunnel_server", Context.MODE_PRIVATE)

    var first: Int
        get() = prefs.getInt("first", TunnelDomains.GOOGLE).takeIf { TunnelDomains.hostname(it) != null } ?: TunnelDomains.GOOGLE
        set(value) { prefs.edit().putInt("first", value).apply() }

    /** Unless chosen otherwise: Google's server as fallback for any other first choice. */
    var second: Int
        get() = prefs.getInt("second", defaultSecond(first)).takeIf { it == TunnelDomains.NONE || TunnelDomains.hostname(it) != null }
            ?: defaultSecond(first)
        set(value) { prefs.edit().putInt("second", value).apply() }

    /** The servers to try, in order. */
    fun order(): List<Int> = listOf(first, second).filter { it != TunnelDomains.NONE }.distinct()

    companion object {
        /** The sensible fallback for [first]: Google's server, which every browser knows, unless that is the first choice. */
        fun defaultSecond(first: Int) = if (first == TunnelDomains.GOOGLE) TunnelDomains.NONE else TunnelDomains.GOOGLE
    }
}
