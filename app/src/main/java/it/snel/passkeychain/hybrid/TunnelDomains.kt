package it.snel.passkeychain.hybrid

import java.security.MessageDigest

/**
 * Tunnel servers, by the 16-bit number the phone puts in its Bluetooth advert
 * (EID bytes 14-15). 0 is Google's cable.ua5v.com, from the browser's built-in
 * list. For 256-65535 the browser computes the hostname itself (Chromium's
 * tunnelserver::DecodeDomain), so anyone can run a server under such a name.
 * server/tunnel-hostnames.py does the same computation.
 */
object TunnelDomains {
    const val GOOGLE = 0
    /** "no second choice" */
    const val NONE = -1
    const val FIRST_COMPUTED = 256
    const val LAST_COMPUTED = 0xFFFF

    private const val BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
    private val TLDS = arrayOf("com", "org", "net", "info")

    /** The hostname for tunnel server [number], or null if the app cannot use that number. */
    fun hostname(number: Int): String? = when (number) {
        GOOGLE -> "cable.ua5v.com"
        in FIRST_COMPUTED..LAST_COMPUTED -> computed(number)
        else -> null
    }

    /** SHA-256("caBLEv2 tunnel server domain" || number (2 bytes, little-endian) || 0x00), base32-encoded. */
    private fun computed(number: Int): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("caBLEv2 tunnel server domain".toByteArray(Charsets.US_ASCII))
        md.update(byteArrayOf((number and 0xFF).toByte(), (number ushr 8).toByte(), 0))
        val digest = md.digest()
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (digest[i].toLong() and 0xFF)
        val tld = TLDS[(v and 3).toInt()]
        v = v ushr 2
        val label = StringBuilder()
        while (v != 0L) {
            label.append(BASE32[(v and 31).toInt()])
            v = v ushr 5
        }
        return "cable.$label.$tld"
    }

    data class Entry(val number: Int, val host: String)

    /** Google, then every computed name, ordered by top-level domain and then alphabetically. */
    val all: List<Entry> by lazy {
        listOf(Entry(GOOGLE, hostname(GOOGLE)!!)) +
            (FIRST_COMPUTED..LAST_COMPUTED).map { Entry(it, computed(it)) }
                .sortedWith(compareBy({ it.host.substringAfterLast('.') }, { it.host }))
    }

    /** [all] narrowed by [query]: a number finds that number, text finds names containing it. */
    fun search(query: String, entries: List<Entry> = all): List<Entry> {
        val q = query.trim().lowercase().removePrefix("#")
        if (q.isEmpty()) return entries
        q.toIntOrNull()?.let { n -> return entries.filter { it.number == n } }
        return entries.filter { q in it.host }
    }
}
