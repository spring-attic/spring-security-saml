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
package org.springframework.security.saml.key;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Verifies that the keyStore class can be initialized and is able to return keys from
 * the keystore which contains one key aliased "apollo".
 *
 * @author Vladimir Schäfer
 */
public class JKSKeyManagerTest {

    private ApplicationContext context;
    private JKSKeyManager keyManager;

    @Before
    public void init() {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        keyManager = (JKSKeyManager) context.getBean("keyStore");
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
        new JKSKeyManager(null, "xxx");
    }

    /**
     * Verifies hat invalid key names return null.
     */
    @Test
    public void testGetEmptyKey() {
        assertNull(keyManager.getPublicKey(""));
        assertNull(keyManager.getPublicKey(null));
    }

    /**
     * Verifies the non existing keys return null.
     */
    @Test
    public void testGetKeyNonExistent() {
        assertNull(keyManager.getPublicKey("apollo111"));
    }

    /**
     * Verifies that the certificate can be retreived.
     */
    @Test
    public void testGetCertificate() {
        assertNotNull(keyManager.getCertificate("apollo"));
    }

    /**
     * Verifies that attempt to load nonexisting certificate will return null.
     */
    @Test
    public void testGetCertificateNonExistent() {
        assertNull(keyManager.getCertificate("apollo13"));
    }

}
