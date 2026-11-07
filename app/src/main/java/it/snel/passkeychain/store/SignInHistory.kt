package it.snel.passkeychain.store

import android.content.Context
import it.snel.passkeychain.model.HistoryEntry
import java.io.File

/**
 * The sign-in history, encrypted like the passkeys (it shows which sites you
 * use). Kept short ([HistoryEntry.MAX] entries) and never exported.
 */
class SignInHistory(context: Context) {
    private val file = File(context.filesDir, "history.enc")

    fun load(): List<HistoryEntry> = synchronized(LOCK) {
        if (!file.exists()) emptyList()
        else runCatching { HistoryEntry.decode(KeystoreCrypto.decrypt(file.readBytes()).toString(Charsets.UTF_8)) }
            .getOrElse { emptyList() }
    }

    /** Adds [entry]; a failure to write is ignored (the sign-in itself matters more). */
    fun add(entry: HistoryEntry) = synchronized(LOCK) {
        runCatching { write(HistoryEntry.add(load(), entry)) }
    }

    fun clear() = synchronized(LOCK) { file.delete() }

    private fun write(list: List<HistoryEntry>) {
        val blob = KeystoreCrypto.encrypt(HistoryEntry.encode(list).toByteArray(Charsets.UTF_8))
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(blob)
        if (!tmp.renameTo(file)) { file.writeBytes(blob); tmp.delete() }
    }

    private companion object {
        /** one lock for all instances: the sign-in screen and the main screen may both write */
        val LOCK = Any()
    }
}
