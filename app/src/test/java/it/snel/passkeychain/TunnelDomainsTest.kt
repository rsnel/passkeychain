package it.snel.passkeychain

import it.snel.passkeychain.hybrid.TunnelDomains
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelDomainsTest {
    @Test fun matchesChromium() {
        // Chromium device/fido/cable/v2_handshake_unittest.cc: KnownDomainID(266)
        assertEquals("cable.wufkweyy3uaxb.com", TunnelDomains.hostname(266))
        assertEquals("cable.ua5v.com", TunnelDomains.hostname(0))
        // same as server/tunnel-hostnames.py
        assertEquals("cable.qz2ekwmnd332c.info", TunnelDomains.hostname(256))
    }

    @Test fun onlyGoogleAndComputedNumbers() {
        assertNull(TunnelDomains.hostname(1))
        assertNull(TunnelDomains.hostname(255))
        assertNull(TunnelDomains.hostname(65536))
        assertTrue(TunnelDomains.hostname(65535)!!.startsWith("cable."))
    }

    @Test fun allIsGoogleThenByTldThenName() {
        val all = TunnelDomains.all
        assertEquals(1 + 65280, all.size)
        assertEquals(0, all[0].number)
        val rest = all.drop(1).map { it.host }
        assertEquals(rest.sortedWith(compareBy({ it.substringAfterLast('.') }, { it })), rest)
        assertTrue(rest.first().endsWith(".com") && rest.last().endsWith(".org"))
    }

    @Test fun searchByNumberOrText() {
        assertEquals(listOf(266), TunnelDomains.search("266").map { it.number })
        assertEquals(listOf(266), TunnelDomains.search("#266").map { it.number })
        assertEquals(listOf(266), TunnelDomains.search("wufkweyy").map { it.number })
        assertTrue(TunnelDomains.search("100").isEmpty())
        assertEquals(TunnelDomains.all.size, TunnelDomains.search("  ").size)
    }
}
