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
package org.springframework.security.saml.storage;

import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.security.saml.parser.SAMLObject;

import javax.servlet.http.HttpSession;
import java.util.Hashtable;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * @author Vladimir Schäfer
 */
public class HttpSessionStorageTest {

    HttpSession session;
    HttpSessionStorage cache;
    AuthnRequest request;

    static String SPRING_SAML_STORAGE_KEY = "_springSamlStorageKey";

    /**
     * Verifies that in case the session doesn't yet contain the SAML storage it will be created.
     */
    @Test
    public void testNonExisting() {
        session = createMock(HttpSession.class);
        expect(session.getId()).andReturn("session123").anyTimes();
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(null);
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(null);
        session.setAttribute(eq(SPRING_SAML_STORAGE_KEY), notNull());

        replay(session);
        cache = new HttpSessionStorage(session);
        assertNull(cache.retrieveMessage("test"));
        assertNotNull(cache.getAllMessages());
        assertEquals(0, cache.getAllMessages().size());
        verify(session);
    }

    /**
     * Verifies that once the session is set (call to getAttribute returns some value), the newly created
     * storage won't try to overwrite the preexisting value.
     */
    @Test
    public void testRaceInitialization() throws Exception {
        session = createMock(HttpSession.class);
        expect(session.getId()).andReturn("session123").anyTimes();
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(null).times(3);
        session.setAttribute(eq(SPRING_SAML_STORAGE_KEY), notNull());
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(new Hashtable());

        replay(session);

        class TestRunner extends Thread {
            public SAMLMessageStorage storage;

            public void start() {
                storage = new HttpSessionStorage(session);
                storage.retrieveMessage("abc123");
            }
        }

        TestRunner a = new TestRunner();
        TestRunner b = new TestRunner();

        // Make both threads verify that the session is empty and wait for the lock
        // After one of the thread receives the lock, it will set the session, while
        // the second must reverify whether it was already set or not
        synchronized (session) {
            a.start();
            b.start();
            synchronized (this) {
                wait(50);
            }
        }

        verify(session);

        assertNotNull(a.storage);
        assertNotNull(b.storage);
    }

    /**
     * Verifies that in case the session already includes the SAML storage, though empty, it behaves
     * as expected.
     */
    @Test
    public void testEmptyExisting() {
        Hashtable<String, SAMLObject> storage = new Hashtable<String, SAMLObject>();
        session = createMock(HttpSession.class);
        expect(session.getId()).andReturn("session123").anyTimes();
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(storage);

        replay(session);
        cache = new HttpSessionStorage(session);
        assertNull(cache.retrieveMessage("test"));
        assertNotNull(cache.getAllMessages());
        assertEquals(0, cache.getAllMessages().size());
        verify(session);
    }

    /**
     * Verifies that in case the session already includes the SAML storage, though empty, it behaves
     * as expected.
     */
    @Test
    public void testNonEmptyExisting() {
        Hashtable<String, SAMLObject> storage = new Hashtable<String, SAMLObject>();
        Audience audienceMock = createNiceMock(Audience.class);
        SAMLObject<Audience> audience = new SAMLObject<Audience>(audienceMock);
        storage.put("testKey", audience);
        session = createMock(HttpSession.class);
        expect(session.getId()).andReturn("session123").anyTimes();
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(storage);
        session.setAttribute(eq(SPRING_SAML_STORAGE_KEY), anyObject());

        replay(session);
        cache = new HttpSessionStorage(session);
        assertNotNull(cache.getAllMessages());
        assertEquals(1, cache.getAllMessages().size());
        assertEquals(audienceMock, cache.retrieveMessage("testKey"));
        verify(session);
    }

    /**
     * Verifies that in case the session already includes the SAML storage and we store another element,
     * it will be accessible until another messages gets retrieved.
     */
    @Test
    public void testInsert() {
        Hashtable<String, SAMLObject> storage = new Hashtable<String, SAMLObject>();
        Audience audienceMock = createNiceMock(Audience.class);
        Assertion assertionMock = createNiceMock(Assertion.class);
        storage.put("testKey", new SAMLObject<Audience>(audienceMock));
        session = createMock(HttpSession.class);
        expect(session.getId()).andReturn("session123").anyTimes();
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(storage);
        session.setAttribute(eq(SPRING_SAML_STORAGE_KEY), anyObject());
        expectLastCall().times(2);

        replay(session);
        cache = new HttpSessionStorage(session);
        cache.storeMessage("testKey2", assertionMock);
        assertEquals(2, cache.getAllMessages().size());
        assertNotNull(cache.getAllMessages());

        assertEquals(assertionMock, cache.retrieveMessage("testKey2"));
        assertEquals(0, cache.getAllMessages().size());
        assertNotNull(cache.getAllMessages());

        assertNull(cache.retrieveMessage("testKey2"));
        verify(session);
    }

    /**
     * Verifies that in case the session already includes the SAML storage and we store another element with
     * the same key as the one already existing, it will be overwritten.
     */
    @Test
    public void testOverwrite() {
        Hashtable<String, SAMLObject> storage = new Hashtable<String, SAMLObject>();
        Audience audienceMock = createNiceMock(Audience.class);
        Assertion assertionMock = createNiceMock(Assertion.class);
        storage.put("testKey", new SAMLObject<Audience>(audienceMock));
        session = createMock(HttpSession.class);
        expect(session.getId()).andReturn("session123").anyTimes();
        expect(session.getAttribute(SPRING_SAML_STORAGE_KEY)).andReturn(storage);
        session.setAttribute(eq(SPRING_SAML_STORAGE_KEY), anyObject());
        expectLastCall().times(2);

        replay(session);
        cache = new HttpSessionStorage(session);
        cache.storeMessage("testKey", assertionMock);
        assertNotNull(cache.getAllMessages());
        assertEquals(1, cache.getAllMessages().size());
        assertEquals(assertionMock, cache.retrieveMessage("testKey"));
        verify(session);
    }
}
