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
package org.springframework.security.saml.util;

import org.junit.Test;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;

/**
 * Test for the SAMLUtil class.
 *
 * @author Vladimir Schaefer
 */
public class SAMLUtilTest {

    @Test
    public void testPopulateLocalEntityNullContext() {
        SAMLUtil.populateLocalEntity(null, null);
    }

    @Test
    public void testPopulateLocalEntityNullPath() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, null);
        assertNull(context.getLocalEntityId());
        assertNull(context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityNoAlias() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, "/SSO");
        assertNull(context.getLocalEntityId());
        assertNull(context.getLocalEntityRole());
    }    

    @Test
    public void testPopulateLocalEntityAliasNoRole() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, "/SSO/alias/my.entity");
        assertEquals("my.entity", context.getLocalEntityId());
        assertNull(context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityAliasSPRole() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, "/SSO/alias/my.entity/sp");
        assertEquals("my.entity", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityAliasIDPRole() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, "/SSO/alias/my.entity/iDp");
        assertEquals("my.entity", context.getLocalEntityId());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityComplexAliasIDPRole() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, "/SSO/alias/http://www.saml.org/test/SSO/idp");
        assertEquals("http://www.saml.org/test/SSO", context.getLocalEntityId());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

    @Test
    public void testPopulateLocalEntityAliasDefaultRole() {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();
        SAMLUtil.populateLocalEntity(context, "/SSO/alias/my.entity/invalid");
        assertEquals("my.entity", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
    }

}