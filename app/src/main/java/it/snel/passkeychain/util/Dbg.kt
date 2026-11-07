package it.snel.passkeychain.util

import android.content.Context
import android.util.Log
import it.snel.passkeychain.BuildConfig

/**
 * All logging goes through here, and is off unless switched on. The switch
 * ("Debug logging" in the menu) only exists in debug builds; a release build
 * never logs. Some messages contain key material (PSK, Noise keys), which must
 * not end up in the system log by default.
 */
object Dbg {
    private const val PREFS = "debug"
    private const val KEY = "logging"

    @Volatile var enabled = false
        private set

    fun init(context: Context) {
        enabled = BuildConfig.DEBUG &&
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, false)
    }

    fun setEnabled(context: Context, on: Boolean) {
        if (!BuildConfig.DEBUG) return
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, on).apply()
        enabled = on
    }

    fun v(tag: String, msg: String) { if (enabled) Log.v(tag, msg) }
    fun d(tag: String, msg: String) { if (enabled) Log.d(tag, msg) }
    fun i(tag: String, msg: String) { if (enabled) Log.i(tag, msg) }
    fun w(tag: String, msg: String) { if (enabled) Log.w(tag, msg) }
    fun w(tag: String, msg: String, t: Throwable) { if (enabled) Log.w(tag, msg, t) }
    fun e(tag: String, msg: String) { if (enabled) Log.e(tag, msg) }
    fun e(tag: String, msg: String, t: Throwable) { if (enabled) Log.e(tag, msg, t) }
}
