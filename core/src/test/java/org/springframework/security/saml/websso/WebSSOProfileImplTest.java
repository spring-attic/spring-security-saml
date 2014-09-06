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
package org.springframework.security.saml.websso;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.storage.StorageFactoryTestImpl;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static junit.framework.Assert.assertNull;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * @author Vladimir Schafer
 */
public class WebSSOProfileImplTest {

    ApplicationContext context;
    WebSSOProfile profile;
    SAMLMessageStorage storage;
    MetadataManager metadata;

    WebSSOProfileOptions options;
    SAMLContextProvider contextProvider;
    HttpServletRequest request;
    HttpServletResponse response;

    ServletOutputStream output;
    SAMLMessageContext samlContext;

    @Before
    public void initialize() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        profile = context.getBean("webSSOprofile", WebSSOProfile.class);
        metadata = context.getBean("metadata", MetadataManager.class);
        options = new WebSSOProfileOptions(null);

        request = createNiceMock(HttpServletRequest.class);
        response = createNiceMock(HttpServletResponse.class);
        output = new ServletOutputStream() {
            public void write(int b) throws IOException {
            }
        };

        storage = createMock(SAMLMessageStorage.class);

        contextProvider = context.getBean("contextProvider", SAMLContextProviderImpl.class);
        ((SAMLContextProviderImpl) contextProvider).setStorageFactory(new StorageFactoryTestImpl(storage));

        expect(request.isSecure()).andReturn(false);
        expect(request.getAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_ENTITY_ID)).andReturn(null);
        expect(request.getContextPath()).andReturn("/");

        replyMock();

        samlContext = contextProvider.getLocalAndPeerEntity(request, response);
        samlContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        samlContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));

        verifyMock();

        expect(response.getOutputStream()).andReturn(output).anyTimes();

    }

    /**
     * Verifies that the processing fails if there are no SP hosted metadata configured.
     *
     * @throws Exception error
     */
    @Test(expected = SAMLException.class)
    public void testNoSPNameSet() throws Exception {
        samlContext.setLocalEntityId(null);
        samlContext.setLocalEntityMetadata(null);
        samlContext.setLocalEntityRole(null);
        samlContext.setLocalEntityRoleMetadata(null);
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that the processing fails if there are no SP hosted metadata configured.
     *
     * @throws Exception error
     */
    @Test(expected = MetadataProviderException.class)
    public void testMissingSP() throws Exception {
        MetadataManager manager = context.getBean("metadata", MetadataManager.class);
        while (manager.getProviders().size() > 0) {
            manager.removeMetadataProvider(manager.getProviders().iterator().next());
            manager.refreshMetadata();
        }
        expect(request.isSecure()).andReturn(false);
        expect(request.getAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_ENTITY_ID)).andReturn(null);
        replyMock();
        samlContext = contextProvider.getLocalAndPeerEntity(request, response);
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that default IDP is used if none is specified
     *
     * @throws Exception error
     */
    @Test
    public void testDefaultIDP() throws Exception {
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that message is signed if POST binding is used and metadata IDP requires requests to be signed.
     *
     * @throws Exception error
     */
    @Test
    public void testPOSTSigned() throws Exception {
        options.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        verifyMock();
        assertTrue(authnRequest.isSigned());
        assertNotNull(authnRequest.getSignature());
    }

    /**
     * Verifies that SAML message is correctly constructed.
     *
     * @throws Exception error
     */
    @Test
    public void testSentCorrectly() throws Exception {

        // Although we set redirect binding, the server only supports POST, so it will be used
        options.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();

        profile.sendAuthenticationRequest(samlContext, options);

        AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        assertNotNull(authnRequest.getID());
        assertNotNull(authnRequest.getIssueInstant());
        assertEquals(false, authnRequest.isForceAuthn());
        assertEquals(false, authnRequest.isPassive());
        assertEquals("http://localhost:8081/spring-security-saml2-webapp", authnRequest.getIssuer().getValue());
        assertEquals("http://localhost:8081/spring-security-saml2-webapp/saml/SSO", authnRequest.getAssertionConsumerServiceURL());
        assertEquals("http://localhost:8080/opensso/SSORedirect/metaAlias/idp", authnRequest.getDestination());
        assertEquals(org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI, authnRequest.getProtocolBinding());
        assertEquals(org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI, samlContext.getPeerEntityEndpoint().getBinding());
        verifyMock();

    }

    /**
     * Verifies that invalid binding name will be ignored and default used instead.
     *
     * @throws Exception error
     */
    @Test(expected = MetadataProviderException.class)
    public void testInvalidBinding() throws Exception {
        options.setBinding("invalid");
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that specifying consumer index which is not supported by the given profile will fail.
     * The referred index uses Holder-of-Key binding.
     *
     * @throws Exception error
     */
    @Test(expected = MetadataProviderException.class)
    public void testUnsupportedConsumerIndex() throws Exception {
        options.setAssertionConsumerIndex(2);
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that specifying consumer index which is not valid will fail.
     *
     * @throws Exception error
     */
    @Test(expected = MetadataProviderException.class)
    public void testInvalidConsumerIndex() throws Exception {
        options.setAssertionConsumerIndex(20);
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that binding unsupported by IDP fails with exception.
     *
     * @throws Exception error
     */
    @Test(expected = MetadataProviderException.class)
    public void testBindingUnsupportedByIDP() throws Exception {
        String idpId = "http://localhost:8080/noBinding";
        samlContext.setPeerEntityId(idpId);
        samlContext.setPeerExtendedMetadata(metadata.getExtendedMetadata(idpId));
        samlContext.setPeerEntityMetadata(metadata.getEntityDescriptor(idpId));
        samlContext.setPeerEntityRoleMetadata(metadata.getRole(idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        options.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that IDP without any SSO binding can't be used.
     *
     * @throws Exception error
     */
    @Test
    public void testNoSigningRequired() throws Exception {
        String idpId = "http://localhost:8080/noSign";
        samlContext.setPeerEntityId(idpId);
        samlContext.setPeerExtendedMetadata(metadata.getExtendedMetadata(idpId));
        samlContext.setPeerEntityMetadata(metadata.getEntityDescriptor(idpId));
        samlContext.setPeerEntityRoleMetadata(metadata.getRole(idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        verifyMock();
        assertTrue(!authnRequest.isSigned());
    }

    /**
     * Verifies that IDP without any SSO binding can't be used.
     *
     * @throws Exception error
     */
    @Test(expected = MetadataProviderException.class)
    public void testNoAvailableBinding() throws Exception {
        String idpId = "http://localhost:8080/noBinding";
        samlContext.setPeerEntityId(idpId);
        samlContext.setPeerExtendedMetadata(metadata.getExtendedMetadata(idpId));
        samlContext.setPeerEntityMetadata(metadata.getEntityDescriptor(idpId));
        samlContext.setPeerEntityRoleMetadata(metadata.getRole(idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
    }

    /**
     * Verifies that passive option is correctly set on outgoing SAML message, if set in options.
     *
     * @throws Exception error
     */
    @Test
    public void testPassive() throws Exception {
        options.setPassive(true);
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        verifyMock();
        assertEquals(false, authnRequest.isForceAuthn());
        assertEquals(true, authnRequest.isPassive());
        assertTrue(authnRequest.getScoping().getProxyCount() > 0);
    }

    /**
     * Verifies that forceAuthN option is correctly set on outgoing SAML message, if set in options.
     *
     * @throws Exception error
     */
    @Test
    public void testForce() throws Exception {
        options.setForceAuthN(true);
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        verifyMock();
        assertEquals(true, authnRequest.isForceAuthn());
        assertEquals(false, authnRequest.isPassive());
        assertTrue(authnRequest.getScoping().getProxyCount() > 0);
    }

    /**
     * Verifies that relay state is set when specified on webSSOProfileOptions.
     *
     * @throws Exception error
     */
    @Test
    public void testSendRelayState() throws Exception {
        options.setRelayState("myRelayState");
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        verifyMock();
        assertEquals("myRelayState", samlContext.getRelayState());
    }

    /**
     * Verfies that proxying is disabled if false is set in options.
     *
     * @throws Exception error
     */
    @Test
    public void testDisallowProxy() throws Exception {
        options.setProxyCount(null);
        storage.storeMessage((String) notNull(), (XMLObject) notNull());
        replyMock();
        profile.sendAuthenticationRequest(samlContext, options);
        AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        verifyMock();
        assertEquals(false, authnRequest.isForceAuthn());
        assertEquals(false, authnRequest.isPassive());
        assertNull(authnRequest.getScoping().getProxyCount());
    }

    private void verifyMock() {
        verify(response);
        verify(request);
        verify(storage);
        reset(response);
        reset(request);
        reset(storage);
    }

    private void replyMock() {
        replay(storage);
        replay(request);
        replay(response);
    }
}
