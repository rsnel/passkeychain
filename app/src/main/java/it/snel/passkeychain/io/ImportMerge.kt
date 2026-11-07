package it.snel.passkeychain.io

import it.snel.passkeychain.model.Passkey

/**
 * What an import does with passkeys that are already on the phone. A passkey
 * is the same one when its credential id and site match. An identical copy is
 * left alone; one that differs (another name, counter or backup state)
 * replaces the stored one.
 */
object ImportMerge {

    class Result(val passkeys: List<Passkey>, val added: Int, val updated: Int, val unchanged: Int) {
        val changed: Boolean get() = added + updated > 0

        /** "Imported 2 new passkeys · 3 already here · 1 updated" */
        fun message(skipped: Int): String {
            val parts = mutableListOf<String>()
            parts += when (added) {
                0 -> "No new passkeys"
                1 -> "Imported 1 new passkey"
                else -> "Imported $added new passkeys"
            }
            if (unchanged > 0) parts += "$unchanged already here"
            if (updated > 0) parts += "$updated updated"
            if (skipped > 0) parts += "$skipped skipped"
            return parts.joinToString(" · ")
        }
    }

    fun merge(existing: List<Passkey>, incoming: List<Passkey>): Result {
        val list = existing.toMutableList()
        var added = 0; var updated = 0; var unchanged = 0
        for (pk in incoming) {
            val i = list.indexOfFirst { it.credentialId == pk.credentialId && it.rpId == pk.rpId }
            when {
                i < 0 -> { list += pk; added++ }
                list[i] == pk -> unchanged++
                else -> { list[i] = pk; updated++ }
            }
        }
        return Result(list, added, updated, unchanged)
    }
}
