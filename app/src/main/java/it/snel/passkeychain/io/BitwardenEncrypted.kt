package it.snel.passkeychain.io

import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Bitwarden's "password protected" encrypted JSON export, so backups and
 * transfers to/from Bitwarden never exist as plain text.
 *
 * Format (bitwarden/clients: base-vault-export.service.ts and
 * bitwarden-password-protected-importer.ts; KDF from bitwarden/sdk-internal):
 *
 *   { "encrypted": true, "passwordProtected": true,
 *     "salt": "<base64 of 16 random bytes; used as a UTF-8 string>",
 *     "kdfType": 0 (PBKDF2-SHA256) | 1 (Argon2id),
 *     "kdfIterations": n, ["kdfMemory": MiB, "kdfParallelism": p,]
 *     "encKeyValidation_DO_NOT_EDIT": EncString(random GUID),
 *     "data": EncString(the ordinary unencrypted JSON export) }
 *
 * key = KDF(password, salt) (32 bytes; Argon2id uses SHA-256(salt) as its salt),
 * stretched with HKDF-Expand-SHA256 into encKey ("enc") and macKey ("mac").
 * EncString type 2: "2.<iv>|<ciphertext>|<mac>" in base64, AES-256-CBC with
 * PKCS#7 padding, mac = HMAC-SHA256(macKey, iv || ciphertext).
 */
object BitwardenEncrypted {

    const val KDF_PBKDF2 = 0
    const val KDF_ARGON2ID = 1

    /** What PassKeyChain writes: Bitwarden's default KDF. */
    const val EXPORT_PBKDF2_ITERATIONS = 600_000

    class WrongPassword : Exception("Wrong password for this backup")
    class Unsupported(message: String) : Exception(message)

    /** True for any Bitwarden encrypted export (password protected or account restricted). */
    fun isEncrypted(text: String): Boolean =
        runCatching { JSONObject(text.trim()).optBoolean("encrypted", false) }.getOrDefault(false)

    fun isPasswordProtected(text: String): Boolean =
        runCatching { JSONObject(text.trim()).let { it.optBoolean("encrypted") && it.optBoolean("passwordProtected") } }
            .getOrDefault(false)

    /** Decrypts a password-protected export and returns the inner (unencrypted) JSON export. */
    fun decrypt(text: String, password: String): String {
        val doc = JSONObject(text.trim())
        if (!doc.optBoolean("encrypted")) throw Unsupported("This file is not encrypted")
        if (!doc.optBoolean("passwordProtected")) throw Unsupported(
            "This is an \"account restricted\" Bitwarden export, which only Bitwarden itself can read. " +
                "Export again with file format .json (Encrypted) and export type \"Password protected\".",
        )
        val salt = doc.getString("salt")
        val keys = deriveKeys(password, salt, kdfFrom(doc))
        // the validation string tells a wrong password apart from a damaged file
        runCatching { EncString.decrypt(doc.getString("encKeyValidation_DO_NOT_EDIT"), keys) }
            .getOrElse { throw WrongPassword() }
        return EncString.decrypt(doc.getString("data"), keys).toString(Charsets.UTF_8)
    }

    /** Encrypts an unencrypted JSON export with [password] (PBKDF2-SHA256, Bitwarden's default). */
    fun encrypt(innerJson: String, password: String, iterations: Int = EXPORT_PBKDF2_ITERATIONS): String {
        require(password.isNotEmpty()) { "empty password" }
        val salt = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val keys = deriveKeys(password, salt, Kdf.Pbkdf2(iterations))
        return JSONObject()
            .put("encrypted", true)
            .put("passwordProtected", true)
            .put("salt", salt)
            .put("kdfType", KDF_PBKDF2)
            .put("kdfIterations", iterations)
            .put("encKeyValidation_DO_NOT_EDIT", EncString.encrypt(UUID.randomUUID().toString().toByteArray(), keys))
            .put("data", EncString.encrypt(innerJson.toByteArray(Charsets.UTF_8), keys))
            .toString(2)
    }

    // ---- key derivation -------------------------------------------------------------

    sealed interface Kdf {
        data class Pbkdf2(val iterations: Int) : Kdf
        data class Argon2id(val iterations: Int, val memoryMiB: Int, val parallelism: Int) : Kdf
    }

    /** The KDF settings from a file, within the bounds Bitwarden's own importer accepts. */
    fun kdfFrom(doc: JSONObject): Kdf {
        fun int(k: String) = if (doc.has(k) && !doc.isNull(k)) doc.getInt(k) else throw Unsupported("missing $k")
        return when (doc.optInt("kdfType", -1)) {
            KDF_PBKDF2 -> int("kdfIterations").let {
                if (it !in 5_000..2_000_000) throw Unsupported("unsupported PBKDF2 iterations $it")
                Kdf.Pbkdf2(it)
            }
            KDF_ARGON2ID -> {
                val t = int("kdfIterations"); val m = int("kdfMemory"); val p = int("kdfParallelism")
                if (t !in 2..10 || m !in 16..1024 || p !in 1..16) throw Unsupported("unsupported Argon2id settings t=$t m=$m p=$p")
                Kdf.Argon2id(t, m, p)
            }
            else -> throw Unsupported("unsupported key derivation (kdfType ${doc.opt("kdfType")})")
        }
    }

    class Keys(val enc: ByteArray, val mac: ByteArray)

    fun deriveKeys(password: String, salt: String, kdf: Kdf): Keys = stretch(masterKey(password, salt, kdf))

    /** The 32-byte key from a password: PBKDF2-SHA256, or Argon2id with SHA-256(salt) as salt. */
    fun masterKey(password: String, salt: String, kdf: Kdf): ByteArray {
        val pw = password.toByteArray(Charsets.UTF_8)
        val saltBytes = salt.toByteArray(Charsets.UTF_8)
        return when (kdf) {
            is Kdf.Pbkdf2 -> pbkdf2Sha256(pw, saltBytes, kdf.iterations, 32)
            is Kdf.Argon2id -> Argon2id.hash(
                pw, MessageDigest.getInstance("SHA-256").digest(saltBytes),
                kdf.iterations, kdf.memoryMiB * 1024, kdf.parallelism, 32,
            )
        }
    }

    /** A master key stretched into an encryption key and a MAC key (HKDF-Expand, "enc" and "mac"). */
    fun stretch(master: ByteArray): Keys =
        Keys(hkdfExpand(master, "enc".toByteArray(), 32), hkdfExpand(master, "mac".toByteArray(), 32))

    fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        require(password.isNotEmpty()) { "empty password" } // also: an HMAC key cannot be empty
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
        val out = ByteArray(length)
        var block = 1; var pos = 0
        while (pos < length) {
            mac.update(salt); mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (i in 1 until iterations) {
                u = mac.doFinal(u)
                for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n); pos += n; block++
        }
        return out
    }

    /** HKDF-Expand (RFC 5869, no extract step) with SHA-256: the KDF output is used as the PRK. */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(prk, "HmacSHA256")) }
        val out = ByteArray(length)
        var t = ByteArray(0); var pos = 0; var counter = 1
        while (pos < length) {
            mac.update(t); mac.update(info); mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n); pos += n; counter++
        }
        return out
    }

    // ---- EncString type 2 (AesCbc256_HmacSha256_B64) --------------------------------

    object EncString {
        private val b64e = Base64.getEncoder()
        private val b64d = Base64.getDecoder()

        fun encrypt(plain: ByteArray, keys: Keys): String {
            val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val ct = Cipher.getInstance("AES/CBC/PKCS5Padding")
                .apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.enc, "AES"), IvParameterSpec(iv)) }
                .doFinal(plain)
            val mac = hmac(keys.mac, iv + ct)
            return "2." + b64e.encodeToString(iv) + "|" + b64e.encodeToString(ct) + "|" + b64e.encodeToString(mac)
        }

        fun decrypt(s: String, keys: Keys): ByteArray {
            val dot = s.indexOf('.')
            if (dot < 0 || s.substring(0, dot) != "2") throw Unsupported("unsupported encryption type in ${s.take(4)}…")
            val parts = s.substring(dot + 1).split("|")
            if (parts.size != 3) throw IllegalArgumentException("malformed encrypted string")
            val iv = b64d.decode(parts[0]); val ct = b64d.decode(parts[1]); val mac = b64d.decode(parts[2])
            if (!MessageDigest.isEqual(mac, hmac(keys.mac, iv + ct))) throw IllegalArgumentException("authentication failed")
            return Cipher.getInstance("AES/CBC/PKCS5Padding")
                .apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(keys.enc, "AES"), IvParameterSpec(iv)) }
                .doFinal(ct)
        }

        private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
    }
}

/**
 * Argon2id (RFC 9106, version 0x13), pure Kotlin: Android has no built-in
 * Argon2, and Bitwarden accounts may use it for their export KDF. Lanes are
 * computed one after the other, which gives the same result as in parallel.
 */
object Argon2id {
    private const val BLOCK_WORDS = 128 // 1 KiB blocks of 64-bit words
    private const val SYNC_POINTS = 4

    fun hash(password: ByteArray, salt: ByteArray, iterations: Int, memoryKiB: Int, parallelism: Int, tagLength: Int): ByteArray {
        require(iterations >= 1 && parallelism >= 1 && memoryKiB >= 8 * parallelism) { "invalid Argon2 parameters" }
        val blocks = 4 * parallelism * (memoryKiB / (4 * parallelism)) // m'
        val laneLength = blocks / parallelism
        val segmentLength = laneLength / SYNC_POINTS
        val needed = blocks.toLong() * BLOCK_WORDS * 8
        val free = Runtime.getRuntime().let { it.maxMemory() - (it.totalMemory() - it.freeMemory()) }
        if (needed > free) throw BitwardenEncrypted.Unsupported("this backup needs ${needed shr 20} MiB of memory to decrypt; only ${free shr 20} MiB is available")
        val mem = LongArray(blocks * BLOCK_WORDS)

        // H0
        val h0 = Blake2b(64).apply {
            for (v in intArrayOf(parallelism, tagLength, memoryKiB, iterations, 0x13, 2)) update(le32(v))
            update(le32(password.size)); update(password)
            update(le32(salt.size)); update(salt)
            update(le32(0)); update(le32(0)) // no secret, no associated data
        }.digest()

        // first two blocks of every lane
        for (lane in 0 until parallelism) {
            for (j in 0..1) {
                val b = hPrime(h0 + le32(j) + le32(lane), 1024)
                val off = (lane * laneLength + j) * BLOCK_WORDS
                for (w in 0 until BLOCK_WORDS) mem[off + w] = le64(b, w * 8)
            }
        }

        val zero = LongArray(BLOCK_WORDS); val input = LongArray(BLOCK_WORDS); val address = LongArray(BLOCK_WORDS)
        val r = LongArray(BLOCK_WORDS); val tmp = LongArray(BLOCK_WORDS)

        for (pass in 0 until iterations) {
            for (slice in 0 until SYNC_POINTS) {
                for (lane in 0 until parallelism) {
                    val dataIndependent = pass == 0 && slice < SYNC_POINTS / 2
                    if (dataIndependent) {
                        input.fill(0)
                        input[0] = pass.toLong(); input[1] = lane.toLong(); input[2] = slice.toLong()
                        input[3] = blocks.toLong(); input[4] = iterations.toLong(); input[5] = 2 // Argon2id
                    }
                    var start = 0
                    if (pass == 0 && slice == 0) {
                        start = 2
                        if (dataIndependent) nextAddresses(address, input, zero, r, tmp)
                    }
                    var curr = lane * laneLength + slice * segmentLength + start
                    var prev = if (curr % laneLength == 0) curr + laneLength - 1 else curr - 1
                    for (i in start until segmentLength) {
                        if (curr % laneLength == 1) prev = curr - 1
                        val rand: Long = if (dataIndependent) {
                            if (i % BLOCK_WORDS == 0) nextAddresses(address, input, zero, r, tmp)
                            address[i % BLOCK_WORDS]
                        } else mem[prev * BLOCK_WORDS]
                        var refLane = ((rand ushr 32) % parallelism).toInt()
                        if (pass == 0 && slice == 0) refLane = lane
                        val sameLane = refLane == lane
                        val refIndex = indexAlpha(pass, slice, i, rand and 0xFFFFFFFFL, sameLane, segmentLength, laneLength)
                        val refBlock = refLane * laneLength + refIndex
                        fillBlock(mem, prev * BLOCK_WORDS, mem, refBlock * BLOCK_WORDS, mem, curr * BLOCK_WORDS, pass != 0, r, tmp)
                        curr++; prev++
                    }
                }
            }
        }

        // final block = XOR of the last block of every lane
        val last = LongArray(BLOCK_WORDS)
        for (lane in 0 until parallelism) {
            val off = (lane * laneLength + laneLength - 1) * BLOCK_WORDS
            for (w in 0 until BLOCK_WORDS) last[w] = last[w] xor mem[off + w]
        }
        val bytes = ByteArray(1024)
        for (w in 0 until BLOCK_WORDS) putLe64(bytes, w * 8, last[w])
        mem.fill(0)
        return hPrime(bytes, tagLength)
    }

    private fun indexAlpha(pass: Int, slice: Int, index: Int, pseudoRand: Long, sameLane: Boolean, segmentLength: Int, laneLength: Int): Int {
        val areaSize: Long = if (pass == 0) {
            if (slice == 0) (index - 1).toLong()
            else if (sameLane) (slice * segmentLength + index - 1).toLong()
            else (slice * segmentLength + if (index == 0) -1 else 0).toLong()
        } else {
            if (sameLane) (laneLength - segmentLength + index - 1).toLong()
            else (laneLength - segmentLength + if (index == 0) -1 else 0).toLong()
        }
        var rel = (pseudoRand * pseudoRand) ushr 32
        rel = areaSize - 1 - ((areaSize * rel) ushr 32)
        val startPos = if (pass != 0 && slice != SYNC_POINTS - 1) ((slice + 1) * segmentLength).toLong() else 0L
        return ((startPos + rel) % laneLength).toInt()
    }

    private fun nextAddresses(address: LongArray, input: LongArray, zero: LongArray, r: LongArray, tmp: LongArray) {
        input[6]++
        fillBlock(zero, 0, input, 0, address, 0, false, r, tmp)
        fillBlock(zero, 0, address, 0, address, 0, false, r, tmp)
    }

    /** next = G(prev, ref) (xor the old next when [withXor], i.e. from the second pass on). */
    private fun fillBlock(
        prevA: LongArray, prevOff: Int, refA: LongArray, refOff: Int, nextA: LongArray, nextOff: Int,
        withXor: Boolean, r: LongArray, tmp: LongArray,
    ) {
        for (w in 0 until BLOCK_WORDS) { r[w] = refA[refOff + w] xor prevA[prevOff + w]; tmp[w] = r[w] }
        if (withXor) for (w in 0 until BLOCK_WORDS) tmp[w] = tmp[w] xor nextA[nextOff + w]
        for (i in 0 until 8) round(r, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
            16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15)
        for (i in 0 until 8) round(r, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49,
            2 * i + 64, 2 * i + 65, 2 * i + 80, 2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113)
        for (w in 0 until BLOCK_WORDS) nextA[nextOff + w] = tmp[w] xor r[w]
    }

    private fun round(v: LongArray, a0: Int, a1: Int, a2: Int, a3: Int, a4: Int, a5: Int, a6: Int, a7: Int,
                      a8: Int, a9: Int, a10: Int, a11: Int, a12: Int, a13: Int, a14: Int, a15: Int) {
        gb(v, a0, a4, a8, a12); gb(v, a1, a5, a9, a13); gb(v, a2, a6, a10, a14); gb(v, a3, a7, a11, a15)
        gb(v, a0, a5, a10, a15); gb(v, a1, a6, a11, a12); gb(v, a2, a7, a8, a13); gb(v, a3, a4, a9, a14)
    }

    private fun fBlaMka(x: Long, y: Long): Long = x + y + 2 * (x and 0xFFFFFFFFL) * (y and 0xFFFFFFFFL)

    private fun gb(v: LongArray, a: Int, b: Int, c: Int, d: Int) {
        v[a] = fBlaMka(v[a], v[b]); v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 32)
        v[c] = fBlaMka(v[c], v[d]); v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 24)
        v[a] = fBlaMka(v[a], v[b]); v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 16)
        v[c] = fBlaMka(v[c], v[d]); v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 63)
    }

    /** H' from RFC 9106 section 3.3: BLAKE2b with arbitrary output length. */
    private fun hPrime(x: ByteArray, outLen: Int): ByteArray {
        if (outLen <= 64) return Blake2b(outLen).apply { update(le32(outLen)); update(x) }.digest()
        val out = ByteArray(outLen)
        var v = Blake2b(64).apply { update(le32(outLen)); update(x) }.digest()
        System.arraycopy(v, 0, out, 0, 32)
        var pos = 32
        while (outLen - pos > 64) {
            v = Blake2b(64).apply { update(v) }.digest()
            System.arraycopy(v, 0, out, pos, 32); pos += 32
        }
        val lastLen = outLen - pos
        v = Blake2b(lastLen).apply { update(v) }.digest()
        System.arraycopy(v, 0, out, pos, lastLen)
        return out
    }

    private fun le32(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())
    private fun le64(b: ByteArray, off: Int): Long {
        var r = 0L
        for (i in 7 downTo 0) r = (r shl 8) or (b[off + i].toLong() and 0xFF)
        return r
    }
    private fun putLe64(b: ByteArray, off: Int, v: Long) { for (i in 0..7) b[off + i] = (v ushr (8 * i)).toByte() }
}

/** BLAKE2b (RFC 7693), unkeyed, output length 1..64 bytes. */
class Blake2b(private val outLen: Int) {
    private val h = IV.copyOf().also { it[0] = it[0] xor (0x01010000L or outLen.toLong()) }
    private val buf = ByteArray(128)
    private var bufLen = 0
    private var t0 = 0L; private var t1 = 0L
    private val m = LongArray(16); private val v = LongArray(16)

    init { require(outLen in 1..64) }

    fun update(data: ByteArray): Blake2b {
        var i = 0
        while (i < data.size) {
            if (bufLen == 128) { increment(128); compress(false); bufLen = 0 }
            val n = minOf(128 - bufLen, data.size - i)
            System.arraycopy(data, i, buf, bufLen, n); bufLen += n; i += n
        }
        return this
    }

    fun digest(): ByteArray {
        increment(bufLen.toLong())
        buf.fill(0, bufLen, 128)
        compress(true)
        val out = ByteArray(outLen)
        for (i in 0 until outLen) out[i] = (h[i / 8] ushr (8 * (i % 8))).toByte()
        return out
    }

    private fun increment(n: Long) {
        val before = t0; t0 += n
        if (java.lang.Long.compareUnsigned(t0, before) < 0) t1++
    }

    private fun compress(last: Boolean) {
        for (i in 0 until 16) {
            var w = 0L
            for (j in 7 downTo 0) w = (w shl 8) or (buf[i * 8 + j].toLong() and 0xFF)
            m[i] = w
        }
        for (i in 0 until 8) { v[i] = h[i]; v[i + 8] = IV[i] }
        v[12] = v[12] xor t0; v[13] = v[13] xor t1
        if (last) v[14] = v[14].inv()
        for (r in 0 until 12) {
            val s = SIGMA[r % 10]
            g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private fun g(a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x; v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 32)
        v[c] = v[c] + v[d]; v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 24)
        v[a] = v[a] + v[b] + y; v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]; v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 63)
    }

    private companion object {
        val IV = longArrayOf(
            0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, 0x3c6ef372fe94f82bL, -0x5ab00ac5a0e2c90fL,
            0x510e527fade682d1L, -0x64fa9773d4c193e1L, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
        )
        val SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        )
    }
}
