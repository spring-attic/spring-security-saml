package org.springframework.security.saml.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests for SAMLUtil class.
 */
public class SAMLUtilTest {

    /**
     * Verifies that values are correctly cleaned to conform with NCName type
     */
    @Test
    public void testNCNameClean() {
        assertNull(SAMLUtil.getNCNameString(null));
        assertEquals("", SAMLUtil.getNCNameString(""));
        assertEquals("_", SAMLUtil.getNCNameString("-"));
        assertEquals("_http___test_8080_context_xyz__3", SAMLUtil.getNCNameString("-http://test:8080/context#xyz=$3"));
        assertEquals("urn_xyz_test", SAMLUtil.getNCNameString("urn:xyz:test"));
        assertEquals("test.user", SAMLUtil.getNCNameString("test.user"));
        assertEquals("test___2", SAMLUtil.getNCNameString("test&^%2"));
    }

}
