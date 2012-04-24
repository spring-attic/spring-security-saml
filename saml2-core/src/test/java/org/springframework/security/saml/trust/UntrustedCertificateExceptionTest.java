/*
 * Copyright 2012 Vladimir Schaefer
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
package org.springframework.security.saml.trust;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.KeyManager;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Test for untrusted certificate exception.
 */
public class UntrustedCertificateExceptionTest {

    ApplicationContext context;
    KeyManager keyManager;

    @Before
    public void init() {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        keyManager = context.getBean("keyManager", KeyManager.class);
    }

    /**
     * Verifies that exception can produce a message about untrusted certificate.
     */
    @Test
    public void testExceptionGetMessage() {
        X509Certificate certificate = keyManager.getCertificate("apollo");
        UntrustedCertificateException exception = new UntrustedCertificateException("Error in cert", new X509Certificate[]{certificate});
        String message = exception.getMessage();
        assertTrue(message.contains("cf:f4:0a:3f:fb:4e:32:a0:4e:65:9d:65:78:d7:45:46:a8:6a:92:32"));
    }

    /**
     * Verifies that message can handle null certificates.
     */
    @Test
    public void testExceptionNullCert(){
        UntrustedCertificateException exception = new UntrustedCertificateException("Error in cert", null);
        String message = exception.getMessage();
        assertNotNull(message);
    }

    /**
     * Verifies that message can handle empty certificates.
     */
    @Test
    public void testExceptionEmptyCert(){
        UntrustedCertificateException exception = new UntrustedCertificateException("Error in cert", new X509Certificate[0]);
        String message = exception.getMessage();
        assertNotNull(message);
    }

}
