/* Copyright 2009 Vladimir Sch�fer
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
package org.springframework.security.saml;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.storage.SAMLMessageStorage;

import static junit.framework.Assert.assertEquals;
import static org.easymock.EasyMock.createMock;
import static org.junit.Assert.assertNull;

/**
 * @author Vladimir Sch�fer
 */
public class SAMLAuthenticationTokenTest {

    SAMLAuthenticationToken token;
    SAMLMessageContext context;
    SAMLMessageStorage storage;

    @Before
    public void initialize() {
        context = new SAMLMessageContext();
        storage = createMock(SAMLMessageStorage.class);
        token = new SAMLAuthenticationToken(context);
    }

    @Test
    public void testInitial() {
        assertEquals(context, token.getCredentials());
        assertNull(token.getPrincipal());
    }

    /**
     * Verifies that the token can't be set as authenticated.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetAuthenticated() {
        token.setAuthenticated(true);
    }

    /**
     * Verifies that the token can't be created without context.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateWithoutContext() {
        token = new SAMLAuthenticationToken(null);
    }
}
