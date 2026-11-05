package it.snel.passkeychain.webauthn

import java.io.ByteArrayOutputStream

/**
 * A deliberately tiny CBOR writer/reader — only the subset WebAuthn/CTAP needs:
 * unsigned/negative ints, byte strings, text strings, arrays and maps.
 * Enough to build COSE_Key blobs and to parse CTAP2 getAssertion requests.
 */
object Cbor {

    // ---- encoding -----------------------------------------------------------
    fun encode(value: Any?): ByteArray {
        val o = ByteArrayOutputStream()
        write(o, value)
        return o.toByteArray()
    }

    private fun write(o: ByteArrayOutputStream, v: Any?) {
        when (v) {
            is Int -> writeLong(o, v.toLong())
            is Long -> writeLong(o, v)
            is ByteArray -> { typeLen(o, 2, v.size.toLong()); o.write(v) }
            is String -> { val b = v.toByteArray(Charsets.UTF_8); typeLen(o, 3, b.size.toLong()); o.write(b) }
            is List<*> -> { typeLen(o, 4, v.size.toLong()); v.forEach { write(o, it) } }
            is Map<*, *> -> {
                typeLen(o, 5, v.size.toLong())
                v.forEach { (k, value) -> write(o, k); write(o, value) }
            }
            else -> throw IllegalArgumentException("unsupported CBOR type: $v")
        }
    }

    private fun writeLong(o: ByteArrayOutputStream, n: Long) {
        if (n >= 0) typeLen(o, 0, n) else typeLen(o, 1, -1 - n)
    }

    private fun typeLen(o: ByteArrayOutputStream, major: Int, len: Long) {
        val m = major shl 5
        when {
            len < 24 -> o.write(m or len.toInt())
            len < 0x100 -> { o.write(m or 24); o.write(len.toInt()) }
            len < 0x10000 -> { o.write(m or 25); o.write((len ushr 8).toInt()); o.write(len.toInt()) }
            len < 0x100000000L -> {
                o.write(m or 26)
                for (s in intArrayOf(24, 16, 8, 0)) o.write((len ushr s).toInt() and 0xFF)
            }
            else -> {
                o.write(m or 27)
                for (s in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) o.write((len ushr s).toInt() and 0xFF)
            }
        }
    }

    // ---- decoding -----------------------------------------------------------
    class Reader(private val b: ByteArray) {
        var pos = 0
        fun decode(): Any? {
            val ib = b[pos++].toInt() and 0xFF
            val major = ib ushr 5
            val info = ib and 0x1F
            val len = readLen(info)
            return when (major) {
                0 -> len
                1 -> -1 - len
                2 -> ByteArray(len.toInt()).also { System.arraycopy(b, pos, it, 0, it.size); pos += it.size }
                3 -> String(b, pos, len.toInt(), Charsets.UTF_8).also { pos += len.toInt() }
                4 -> (0 until len).map { decode() }
                5 -> LinkedHashMap<Any?, Any?>().apply { repeat(len.toInt()) { put(decode(), decode()) } }
                else -> throw IllegalArgumentException("unsupported CBOR major $major")
            }
        }
        private fun readLen(info: Int): Long = when (info) {
            in 0..23 -> info.toLong()
            24 -> (b[pos++].toInt() and 0xFF).toLong()
            25 -> { var v = 0L; repeat(2) { v = (v shl 8) or (b[pos++].toLong() and 0xFF) }; v }
            26 -> { var v = 0L; repeat(4) { v = (v shl 8) or (b[pos++].toLong() and 0xFF) }; v }
            27 -> { var v = 0L; repeat(8) { v = (v shl 8) or (b[pos++].toLong() and 0xFF) }; v }
            else -> throw IllegalArgumentException("indefinite lengths unsupported")
        }
    }

    fun decode(bytes: ByteArray): Any? = Reader(bytes).decode()
}
