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

import org.apache.commons.ssl.HostnameVerifier;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static org.easymock.EasyMock.*;
import static org.springframework.security.saml.SAMLTestHelper.setLocalContextParameters;

/**
 * Test for the SAMLUtil class.
 *
 * @author Vladimir Schaefer
 */
public class SAMLContextProviderImplTest {

    HttpServletRequest request;
    HttpServletResponse response;

    ApplicationContext context;
    SAMLContextProviderImpl contextProvider;
    MetadataManager metadata;

    @Before
    public void init() {

        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        contextProvider = (SAMLContextProviderImpl) context.getBean("contextProvider");
        metadata = (MetadataManager) context.getBean("metadata");
        request = createMock(HttpServletRequest.class);
        response = createMock(HttpServletResponse.class);

    }

    protected void replayMock() {
        replay(request);
        replay(response);
    }

    protected  void verifyMock() {
        verify(request);
        verify(response);
    }

    @Test
    public void testPopulateLocalEntityNullPath() throws Exception {
        setLocalContextParameters(request, "", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals(metadata.getHostedSPName(), context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        assertEquals(context.getLocalSSLHostnameVerifier(), HostnameVerifier.DEFAULT);
        verifyMock();
    }

    @Test
    public void testPopulateLocalEntityNoAlias() throws Exception {
        setLocalContextParameters(request, "/SSO", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals(metadata.getHostedSPName(), context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }    

    @Test
    public void testPopulateLocalEntityAliasNoRole() throws Exception {
        setLocalContextParameters(request, "/SSO/alias/myAlias", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        assertEquals(context.getLocalSSLHostnameVerifier(), HostnameVerifier.STRICT);
        verifyMock();
    }

    @Test
    public void testPopulateLocalEntityAliasSPRole() throws Exception {
        setLocalContextParameters(request, "/SSO/alias/myAlias/sp", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test
    public void testPopulateLocalEntityAliasDefaultRole() throws Exception {
        setLocalContextParameters(request, "/SSO/alias/myAlias/invalid", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test(expected = MetadataProviderException.class)
    public void testPopulateLocalEntityAliasInvalidRole() throws Exception {
        setLocalContextParameters(request, "/SSO/alias/myAlias/idp", null);
        replayMock();
        contextProvider.getLocalEntity(request, response);
    }

    @Test
    public void testPopulateLocalEntityAliasIDPRole() throws Exception {
        setLocalContextParameters(request, "/SSO/alias/myIdpAlias/iDp", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("http://localhost:8080/noSign", context.getLocalEntityId());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test(expected = MetadataProviderException.class)
    public void testPopulateLocalEntityComplexAliasIDPRole_missingRole_SP() throws Exception {
        setLocalContextParameters(request, "/saml/SSO/test/alias/myIdpAlias/test", null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("http://localhost:8080/noSign", context.getLocalEntityId());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test
    public void testPopulateCredentialLocalEntity() throws Exception {
        setLocalContextParameters(request, "/", "testSP2");
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test(expected = MetadataProviderException.class)
    public void testPopulateCredentialLocalEntity_invalidName() throws Exception {
        setLocalContextParameters(request, "/", "ABC");
        replayMock();
        contextProvider.getLocalEntity(request, response);
        verifyMock();
    }

}
