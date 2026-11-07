package it.snel.passkeychain

import it.snel.passkeychain.model.HistoryEntry
import it.snel.passkeychain.model.HistoryEntry.Outcome
import it.snel.passkeychain.model.HistoryEntry.Via
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryEntryTest {

    private fun e(time: Long, outcome: Outcome = Outcome.SignedIn, cred: String = "c1", rp: String = "example.com") =
        HistoryEntry(time, rp, "sam@example.com", cred, Via.Computer, outcome, if (outcome == Outcome.Failed) "why" else "")

    @Test fun roundTripsThroughJson() {
        val list = listOf(e(3), e(2, Outcome.Failed), e(1, Outcome.Denied))
        assertEquals(list, HistoryEntry.decode(HistoryEntry.encode(list)))
    }

    @Test fun unreadableHistoryIsEmptyNotFatal() {
        assertTrue(HistoryEntry.decode("not json").isEmpty())
        assertEquals(1, HistoryEntry.decode("""[{"time":5,"rpId":"a","via":"Computer","outcome":"SignedIn"},{"bad":true}]""").size)
    }

    @Test fun keepsTheNewestFirstAndAtMostMax() {
        var list = emptyList<HistoryEntry>()
        for (t in 1..(HistoryEntry.MAX + 25).toLong()) list = HistoryEntry.add(list, e(t))
        assertEquals(HistoryEntry.MAX, list.size)
        assertEquals((HistoryEntry.MAX + 25).toLong(), list.first().time)
    }

    @Test fun lastUsedCountsOnlySuccessForThatPasskey() {
        val list = listOf(e(50, Outcome.Failed), e(40), e(45, cred = "other"), e(60, Outcome.Denied), e(30))
        assertEquals(40L, HistoryEntry.lastUsed(list, "c1", "example.com"))
        assertEquals(null, HistoryEntry.lastUsed(list, "c1", "elsewhere.org"))
    }
}
