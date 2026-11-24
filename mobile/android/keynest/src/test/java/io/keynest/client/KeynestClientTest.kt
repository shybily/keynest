package io.keynest.client

import org.junit.Assert.assertEquals
import org.junit.Test

class KeynestClientTest {
    @Test
    fun renderFormatNamesMatchWireProtocol() {
        assertEquals("env", KeynestRenderFormat.ENV.wireName)
        assertEquals("yaml", KeynestRenderFormat.YAML.wireName)
    }

    @Test
    fun addressStoresScope() {
        val address = KeynestAddress("project", "prod", "api")
        assertEquals("project", address.project)
        assertEquals("prod", address.environment)
        assertEquals("api", address.service)
    }
}
