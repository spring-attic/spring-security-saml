/* Copyright 2011 Vladimir Schäfer
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
package org.springframework.security.saml.metadata;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.key.KeyManager;

import java.io.File;

import static junit.framework.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * @author Vladimir Schäfer
 */
public class MetadataManagerSignaturesTest {

    ApplicationContext context;
    KeyManager keyManager;
    MetadataManager manager;
    ParserPool pool;

    @Before
    public void initialize() throws Exception {

        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        keyManager = context.getBean("keyManager", KeyManager.class);
        manager = context.getBean("metadata", MetadataManager.class);
        pool = context.getBean("parserPool", ParserPool.class);

        System.setProperty("com.sun.security.enableCRLDP", "false");
        System.setProperty("ocsp.enable", "false");

    }

    /**
     * Test verifies that entity is not loaded once signature is required but it is missing from the entity.
     *
     * @throws Exception error
     */
    @Test
    public void testMissingSignature() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testIDP.xml");
        provider.setMetadataRequireSignature(true);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity wasn't loaded
        assertNull(manager.getEntityDescriptor("http://localhost:8080/opensso"));

    }

    /**
     * Test verifies that entity is loaded once signature missing but not required.
     *
     * @throws Exception error
     */
    @Test
    public void testMissingSignature_notRequired() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testIDP.xml");
        provider.setMetadataRequireSignature(false);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNotNull(manager.getEntityDescriptor("http://localhost:8080/opensso"));

    }

    /**
     * Test verifies that self-signed metadata with key provided in the key store is accepted.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_validSelfSigned() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed.xml");
        provider.setMetadataRequireSignature(true);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNotNull(manager.getEntityDescriptor("http://localhost/spring-security-saml2-sample"));

    }

    /**
     * Test verifies that CA signed metadata with CA key provided in the key store is accepted.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_validCA() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_ca.xml");
        provider.setMetadataRequireSignature(true);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNotNull(manager.getEntityDescriptor("localhost"));

    }

    /**
     * Test verifies that metadata signed by trusted CA but with intermediary certificate missing is skipped.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_missing_intermediaryCA() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_ca2.xml");
        provider.setMetadataRequireSignature(true);
        provider.setMetadataTrustCheck(true);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was not loaded
        assertNull(manager.getEntityDescriptor("test_ca2"));

    }

    /**
     * Test verifies that metadata which would fail trust check is accepted once trust validation is disabled.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_missing_intermediaryCA_ignore_trust() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_ca2.xml");
        provider.setMetadataRequireSignature(true);
        provider.setMetadataTrustCheck(false);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNotNull(manager.getEntityDescriptor("test_ca2"));

    }

    /**
     * Test verifies situation when trust store contains a main CA and the certificate of the metadata contain an
     * intermediary and end certificate. Trust should be based on the main CA and metadata accepted.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_chain_CA() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_ca2_chain.xml");
        provider.setMetadataRequireSignature(true);
        provider.setMetadataTrustCheck(true);
        provider.setForceMetadataRevocationCheck(false);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNotNull(manager.getEntityDescriptor("test_ca2"));

    }

    /**
     * Verifies that once CRL checking is enabled the metadata is ignored as CRL can't be located.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_chain_CA_noCRL() throws Exception {

        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("ocsp.enable", "true");

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_ca2_chain.xml");
        provider.setMetadataRequireSignature(true);
        provider.setMetadataTrustCheck(true);
        provider.setForceMetadataRevocationCheck(true);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNull(manager.getEntityDescriptor("test_ca2"));

    }

    /**
     * Test verifies that invalid signature is rejected.
     *
     * @throws Exception error
     */
    @Test
    public void testSignature_invalidSelfSigned() throws Exception {

        ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_invalid.xml");
        provider.setMetadataRequireSignature(true);

        manager.addMetadataProvider(provider);
        manager.refreshMetadata();

        // Make sure entity was loaded
        assertNull(manager.getEntityDescriptor("http://localhost/spring-security-saml2-sample"));

    }

    protected ExtendedMetadataDelegate getMetadata(String fileName) throws Exception {
        File file = context.getResource(fileName).getFile();
        FilesystemMetadataProvider innterProvider = new FilesystemMetadataProvider(file);
        innterProvider.setParserPool(pool);
        return new ExtendedMetadataDelegate(innterProvider);
    }

}
