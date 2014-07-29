/* Copyright 2009 Vladimir Schafer
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
package org.springframework.security.saml.key;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Verifies that the keyStore class can be initialized and is able to return keys from
 * the keystore which contains one key aliased "apollo".
 *
 * @author Vladimir Schafer
 */
public class JKSKeyManagerTest {

    private ApplicationContext context;
    private JKSKeyManager keyManager;

    @Before
    public void init() {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        keyManager = (JKSKeyManager) context.getBean("keyManager");
    }

    /**
     * Verifies that the keystore can be loaded.
     */
    @Test
    public void testGetKeystore() {
        assertNotNull(keyManager.getKeyStore());
    }

    /**
     * Verifies that the keys can be retreived from the store.
     */
    @Test
    public void testGetKey() {
        assertNotNull(keyManager.getPublicKey("apollo"));
    }

    /**
     * Verifies that error during initialization leads to runtime exception.
     */
    @Test(expected = RuntimeException.class)
    public void testInitialize() {
        new JKSKeyManager(null, "xxx", null, null);
    }

    /**
     * Verifies that invalid key names return null.
     */
    @Test
    public void testGetEmptyKey() {
        assertNull(keyManager.getPublicKey(""));
        assertNull(keyManager.getPublicKey(null));
    }

    /**
     * Verifies that non existing keys return null.
     */
    @Test
    public void testGetKeyNonExistent() {
        assertNull(keyManager.getPublicKey("apollo111"));
    }

    /**
     * Verifies that the certificate can be retrieved.
     */
    @Test
    public void testGetCertificate() {
        assertNotNull(keyManager.getCertificate("apollo"));
    }

    /**
     * Verifies that attempt to load nonexistent certificate will return null.
     */
    @Test
    public void testGetCertificateNonExistent() {
        assertNull(keyManager.getCertificate("apollo13"));
    }
}
