package org.springframework.security.saml.util;

import org.joda.time.DateTime;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

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

    @Test
    public void isDateTimeSkewShouldReturnTrueForMaxIntegerForwardInterval() {
        assertTrue(SAMLUtil.isDateTimeSkewValid(60, Integer.MAX_VALUE, new DateTime()));
    }

    @Test
    public void isDateTimeSkewShouldReturnTrueForZeroForwardInterval() {
       assertTrue(SAMLUtil.isDateTimeSkewValid(60, 0, new DateTime()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void isDateTimeSkewShouldThrowErrorForForwardIntervalHigherThanInteger() {
        SAMLUtil.isDateTimeSkewValid(60, Integer.MAX_VALUE+1L, new DateTime());
    }

    @Test(expected = IllegalArgumentException.class)
    public void isDateTimeSkewShouldThrowErrorForForwardIntervalLessThanZero() {
        SAMLUtil.isDateTimeSkewValid(60, -1, new DateTime());
    }
}
