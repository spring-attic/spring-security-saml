/* Copyright 2010 Vladimir Schäfer
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
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author Vladimir Schäfer
 */
public class MetadataManagerTest {

    ApplicationContext context;
    MetadataManager manager;

    @Before
    public void initialize() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        manager = context.getBean("metadata", MetadataManager.class);
    }

    /**
     * Test verifies that metadata defined in Spring descriptor are loaded correctly, including
     * EntityDescriptors defined as nested.
     *
     * @throws Exception error
     */
    @Test
    public void testParseMetadata() throws Exception {

        assertEquals("nest3", manager.getDefaultIDP());
        assertEquals("hostedSP", manager.getHostedSPName());
        assertEquals(3, manager.getIDPEntityNames().size());
        assertTrue(manager.getIDPEntityNames().contains("nest1"));
        assertTrue(manager.getIDPEntityNames().contains("nest2"));
        assertTrue(manager.getIDPEntityNames().contains("nest3"));
        assertEquals(1, manager.getSPEntityNames().size());
        assertTrue(manager.getSPEntityNames().contains("http://localhost:8081/spring-security-saml2-webapp"));

        assertNotNull(manager.getEntityDescriptor("nest1"));
        assertNotNull(manager.getEntityDescriptor("nest2"));
        assertNotNull(manager.getEntityDescriptor("nest3"));
        assertNotNull(manager.getEntityDescriptor("http://localhost:8081/spring-security-saml2-webapp"));
    }
}
