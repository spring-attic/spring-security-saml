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
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLTestBase;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static junit.framework.Assert.assertEquals;
import static org.easymock.EasyMock.*;

/**
 * Test for the SAMLUtil class.
 *
 * @author Vladimir Schaefer
 */
public class SAMLContextProviderImplTest extends SAMLTestBase {

    HttpServletRequest request;
    HttpServletResponse response;

    SAMLCredential credential;
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

    protected SAMLCredential getCredential(String localEntityID) {
        NameID nameID = ((SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
        Assertion assertion = ((SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME)).buildObject();
        nameID.setValue("testName");
        assertion.setID("testID");
        credential = new SAMLCredential(nameID, assertion, "testIDP", localEntityID);
        return credential;
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
        expect(request.getContextPath()).andReturn("");
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals(metadata.getHostedSPName(), context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test
    public void testPopulateLocalEntityNoAlias() throws Exception {
        expect(request.getContextPath()).andReturn("/SSO");
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals(metadata.getHostedSPName(), context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }    

    @Test
    public void testPopulateLocalEntityAliasNoRole() throws Exception {
        expect(request.getContextPath()).andReturn("/SSO/alias/myAlias");
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test
    public void testPopulateLocalEntityAliasSPRole() throws Exception {
        expect(request.getContextPath()).andReturn("/SSO/alias/myAlias/sp");
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test
    public void testPopulateLocalEntityAliasDefaultRole() throws Exception {
        expect(request.getContextPath()).andReturn("/SSO/alias/myAlias/invalid");
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test(expected = MetadataProviderException.class)
    public void testPopulateLocalEntityAliasInvalidRole() throws Exception {
        expect(request.getContextPath()).andReturn("/SSO/alias/myAlias/idp");
        replayMock();
        contextProvider.getLocalEntity(request, response);
    }

    @Test
    public void testPopulateLocalEntityAliasIDPRole() throws Exception {
        expect(request.getContextPath()).andReturn("/SSO/alias/myIdpAlias/iDp");
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("http://localhost:8080/noSign", context.getLocalEntityId());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test(expected = MetadataProviderException.class)
    public void testPopulateLocalEntityComplexAliasIDPRole_missingRole_SP() throws Exception {
        expect(request.getContextPath()).andReturn("/saml/SSO/test/alias/myIdpAlias/test");
        replayMock();
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        assertEquals("http://localhost:8080/noSign", context.getLocalEntityId());
        assertEquals(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test
    public void testPopulateCredentialLocalEntity() throws Exception {
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        replayMock();
        SAMLCredential credential = getCredential("testSP2");
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response, credential);
        assertEquals("testSP2", context.getLocalEntityId());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_NAME, context.getLocalEntityRole());
        verifyMock();
    }

    @Test(expected = MetadataProviderException.class)
    public void testPopulateCredentialLocalEntity_invalidName() throws Exception {
        replayMock();
        SAMLCredential credential = getCredential(null);
        contextProvider.getLocalEntity(request, response, credential);
    }

}
