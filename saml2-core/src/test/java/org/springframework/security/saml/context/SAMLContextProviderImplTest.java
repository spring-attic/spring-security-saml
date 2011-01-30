/*
 * Copyright 2009-2010 Vladimir Schaefer
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
package org.springframework.security.saml.context;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;

/**
 * Test for the SAMLUtil class.
 *
 * @author Vladimir Schaefer
 */
public class SAMLContextProviderImplTest {

    SAMLContextProviderImpl contextProvider;

    @Before
    public void init() {
        contextProvider = new SAMLContextProviderImpl();
    }

    @Test
    public void testPopulateLocalEntityNullContext() {
        contextProvider.populateLocalAlias(null, null);
    }

    @Test
    public void testPopulateLocalEntityNullPath() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, null);
        assertNull(context.getLocalEntityId());
        assertNull(context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityNoAlias() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, "/SSO");
        assertNull(context.getLocalEntityId());
        assertNull(context.getLocalEntityRole());
    }    

    @Test
    public void testPopulateLocalEntityAliasNoRole() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, "/SSO/alias/my.entity");
        assertEquals("my.entity", context.getLocalAlias());
        assertNull(context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityAliasSPRole() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, "/SSO/alias/my.entity/sp");
        assertEquals("my.entity", context.getLocalAlias());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityAliasIDPRole() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, "/SSO/alias/my.entity/iDp");
        assertEquals("my.entity", context.getLocalAlias());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityComplexAliasIDPRole() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, "/SSO/alias/http://www.saml.org/test/SSO/idp");
        assertEquals("http://www.saml.org/test/SSO", context.getLocalAlias());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityAliasDefaultRole() {
        SAMLMessageContext context = new SAMLMessageContext();
        contextProvider.populateLocalAlias(context, "/SSO/alias/my.entity/invalid");
        assertEquals("my.entity", context.getLocalAlias());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

}
