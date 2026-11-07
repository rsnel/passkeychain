package it.snel.passkeychain

import it.snel.passkeychain.io.ImportMerge
import it.snel.passkeychain.model.Passkey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ImportMergeTest {
    private fun pk(id: String, rp: String = "example.com", name: String = "sam", backedUp: Boolean = true) =
        Passkey(credentialId = id, keyValuePkcs8 = "k$id", rpId = rp, userHandle = "u", userName = name, backedUp = backedUp)

    @Test fun newSameAndChangedAreTold() {
        val have = listOf(pk("a"), pk("b"), pk("c", backedUp = false))
        val r = ImportMerge.merge(have, listOf(pk("a"), pk("b", name = "sam2"), pk("c"), pk("d"), pk("a", rp = "other.org")))
        assertEquals(2, r.added)       // d, and a for another site
        assertEquals(2, r.updated)     // b renamed, c now backed up
        assertEquals(1, r.unchanged)   // a
        assertEquals(5, r.passkeys.size)
        assertEquals("sam2", r.passkeys.first { it.credentialId == "b" }.userName)
        assertEquals("Imported 2 new passkeys · 1 already here · 2 updated", r.message(0))
    }

    @Test fun reimportingTheSameFileChangesNothing() {
        val have = listOf(pk("a"), pk("b"))
        val r = ImportMerge.merge(have, have)
        assertTrue(!r.changed)
        assertEquals("No new passkeys · 2 already here · 1 skipped", r.message(1))
    }
}
