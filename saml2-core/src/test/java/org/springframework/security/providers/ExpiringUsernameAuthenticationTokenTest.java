/* Copyright 2009 Vladimir Schäfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.providers;

import org.joda.time.DateTime;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Date;
import java.util.LinkedList;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test for the ExpiringUsernameAuthenticationToken.
 *
 * @author Vladimir Schäfer
 */
public class ExpiringUsernameAuthenticationTokenTest {

    /**
     * Verifies that in case expiration date is not set the token is valid.
     *
     * @throws Exception error
     */
    @Test
    public void testExpirationNull() throws Exception {
        ExpiringUsernameAuthenticationToken t = new ExpiringUsernameAuthenticationToken(null, null, null, new LinkedList<GrantedAuthority>());
        assertTrue(t.isAuthenticated());
    }

    /**
     * Verifies that in case expiration date is set to the future the token is valid.
     *
     * @throws Exception error
     */
    @Test
    public void testExpirationFuture() throws Exception {
        Date future = new DateTime().plusHours(2).toDate();
        ExpiringUsernameAuthenticationToken t = new ExpiringUsernameAuthenticationToken(future, null, null, new LinkedList<GrantedAuthority>());
        assertTrue(t.isAuthenticated());
    }

    /**
     * Verifies that token changes from valid to invalid when time passes over the change point.
     *
     * @throws Exception error
     */
    @Test
    public void testExpirationFutureChange() throws Exception {
        Date future = new DateTime().plusMillis(1000).toDate();
        ExpiringUsernameAuthenticationToken t = new ExpiringUsernameAuthenticationToken(future, null, null, new LinkedList<GrantedAuthority>());
        assertTrue(t.isAuthenticated());
        synchronized (this) {
            wait(1000);
        }
        assertFalse(t.isAuthenticated());
    }

    /**
     * Verifies that constructor without expiration is always non authenticated..
     *
     * @throws Exception error
     */
    @Test
    public void testNonAuthenticatedToken() throws Exception {
        ExpiringUsernameAuthenticationToken t = new ExpiringUsernameAuthenticationToken(null, null);
        assertFalse(t.isAuthenticated());
    }
}
