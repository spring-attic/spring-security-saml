/* Copyright 2011 Vladimir Schaefer
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
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import static junit.framework.Assert.*;

/**
 * Test for metadata generator.
 */
public class MetadataGeneratorTest {

    ApplicationContext context;
    MetadataGenerator generator;

    @Before
    public void init() {

        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        generator = context.getBean("metadataGenerator", MetadataGenerator.class);

    }

    /**
     * Test verifies that metadata can be generated.
     */
    @Test
    public void testGenerateMetadata() {

        generator.setEntityBaseURL("http://localhost");
        generator.setEntityId("my_entity");
        generator.setIncludeDiscoveryExtension(true);
        EntityDescriptor metadata = generator.generateMetadata();

        assertEquals("my_entity", metadata.getEntityID());
        SPSSODescriptor spssoDescriptor = metadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        assertNotNull(spssoDescriptor);

        // Discovery
        assertNotNull(spssoDescriptor.getExtensions());
        assertNotNull(spssoDescriptor.getExtensions().getUnknownXMLObjects());
        assertTrue(spssoDescriptor.getExtensions().getUnknownXMLObjects().size() == 1);

    }

    /**
     * Test verifies that metadata can be generated.
     */
    @Test
    public void testGenerateExtendedMetadata() {

        ExtendedMetadata extendedMetadata;

        generator.setEntityAlias("testAlias");
        generator.setEntityBaseURL("http://localhost:8080");

        // Default generation
        extendedMetadata = generator.generateExtendedMetadata();
        assertEquals("testAlias", extendedMetadata.getAlias());
        assertTrue(extendedMetadata.isLocal());
        assertTrue(extendedMetadata.isIdpDiscoveryEnabled());
        assertEquals("http://localhost:8080/saml/discovery/alias/testAlias", extendedMetadata.getIdpDiscoveryURL());
        assertEquals("http://localhost:8080/saml/login/alias/testAlias?disco=true", extendedMetadata.getIdpDiscoveryResponseURL());

        // Disabled discovery
        generator.setIncludeDiscovery(false);
        generator.setIncludeDiscoveryExtension(false);
        extendedMetadata = generator.generateExtendedMetadata();
        assertFalse(extendedMetadata.isIdpDiscoveryEnabled());
        assertNull(extendedMetadata.getIdpDiscoveryURL());
        assertNull(extendedMetadata.getIdpDiscoveryResponseURL());

        // Default extended metadata
        ExtendedMetadata defaultMetadata = new ExtendedMetadata();
        defaultMetadata.setRequireLogoutResponseSigned(true);
        generator.setExtendedMetadata(defaultMetadata);
        generator.setIncludeDiscovery(true);
        generator.setIncludeDiscoveryExtension(true);
        generator.setCustomDiscoveryResponseURL("http://testDisco.com/response");
        extendedMetadata = generator.generateExtendedMetadata();
        assertTrue(extendedMetadata.isIdpDiscoveryEnabled());
        assertEquals("http://localhost:8080/saml/discovery/alias/testAlias", extendedMetadata.getIdpDiscoveryURL());
        assertEquals("http://testDisco.com/response", extendedMetadata.getIdpDiscoveryResponseURL());
        assertTrue(extendedMetadata.isRequireLogoutResponseSigned());

    }

}
