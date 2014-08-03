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
package org.springframework.security.saml;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Vladimir Schafer
 */
public class SAMLEntryPointTest {

    ApplicationContext context;
    ServletContext servletContext;
    SAMLEntryPoint entryPoint;
    WebSSOProfile ssoProfile;

    HttpSession session;
    HttpServletRequest request;
    HttpServletResponse response;

    MetadataManager metadata;

    @Before
    public void initialize() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        entryPoint = (SAMLEntryPoint) context.getBean("samlEntryPoint");
        servletContext = createMock(ServletContext.class);
        metadata = (MetadataManager) context.getBean("metadata");
        ssoProfile = createMock(WebSSOProfile.class);
        entryPoint.setWebSSOprofile(ssoProfile);
        entryPoint.setServletContext(servletContext);
        request = createMock(HttpServletRequest.class);
        response = createMock(HttpServletResponse.class);
        session = createMock(HttpSession.class);
    }

    @Test
    public void testInitial() {
        assertEquals(ssoProfile, entryPoint.webSSOprofile);
        assertEquals("/saml/login", SAMLEntryPoint.FILTER_URL);
    }

    /**
     * Verifies that URLs are accepted as expected
     */
    @Test
    public void testProcessFilter() {

        expect(request.getRequestURI()).andReturn("/web/saml/login");
        expect(request.getRequestURI()).andReturn("/saml/login");
        expect(request.getRequestURI()).andReturn("/saml");
        expect(request.getRequestURI()).andReturn("/login/");
        expect(request.getRequestURI()).andReturn("/saml/login/");

        replayMock();
        assertTrue(entryPoint.processFilter(request));
        assertTrue(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        assertTrue(entryPoint.processFilter(request));
        verifyMock();
    }

    /**
     * Verifies that if no alternative filter suffix is set the value "/saml/login" is used.
     */
    @Test
    public void testProcessFilterDefault() {

        expect(request.getRequestURI()).andReturn("/web/saml/login");
        expect(request.getRequestURI()).andReturn("/saml/login");
        expect(request.getRequestURI()).andReturn("/login");
        expect(request.getRequestURI()).andReturn("/sso/");
        expect(request.getRequestURI()).andReturn("/login/sso/");

        replayMock();
        assertTrue(entryPoint.processFilter(request));
        assertTrue(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        verifyMock();
    }

    /**
     * Verifies that entry point will redirect user to IDP selection when discovery is enabled and no IDP was
     * specified in request. Default URL for local IDP Discovery Service is used as not URL is in extended metadata.
     *
     * @throws Exception error
     */
    @Test
    public void testIDPSelection_defaultURL() throws Exception {

        expect(request.getSession(true)).andReturn(session);
        expect(request.getHeader("Accept")).andReturn("text/html");
        expect(request.getHeader(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_HEADER)).andReturn(null);
        expect(request.getParameter(SAMLEntryPoint.DISCOVERY_RESPONSE_PARAMETER)).andReturn("false");
        SAMLTestHelper.setLocalContextParameters(request, "/samlApp", null);
        SAMLTestHelper.setPeerContextParameters(request, null, null);
        expect(request.getAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_CONTEXT_PATH)).andReturn("/samlApp");
        response.sendRedirect("/samlApp/saml/discovery?returnIDParam=idp&entityID=http://localhost:8081/spring-security-saml2-webapp");

        replayMock();
        entryPoint.commence(request, response, null);
        verifyMock();

    }

    /**
     * Verifies that entry point will redirect user to IDP selection when discovery is enabled and no IDP was
     * specified in request. URL from metadata is used in this case.
     *
     * @throws Exception error
     */
    @Test
    public void testIDPSelection_metadataURL() throws Exception {

        SAMLMessageContext context = new SAMLMessageContext();
        ExtendedMetadata metadata = new ExtendedMetadata();
        metadata.setIdpDiscoveryEnabled(true);
        metadata.setIdpDiscoveryURL("http://test.fi/idpDisco/");
        context.setLocalExtendedMetadata(metadata);
        context.setLocalEntityId("localId");

        context.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        context.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));

        response.sendRedirect("http://test.fi/idpDisco/?entityID=localId&returnIDParam=idp");

        replayMock();
        entryPoint.initializeDiscovery(context);
        verifyMock();

    }

    /**
     * Verifies that entry point will redirect user to IDP selection when discovery is enabled and no IDP was
     * specified in request. The test should fail as the specfied url is invalid.
     *
     * @throws Exception error
     */
    @Test(expected = IllegalArgumentException.class)
    public void testIDPSelection_invalidDiscoURL() throws Exception {

        SAMLMessageContext context = new SAMLMessageContext();
        ExtendedMetadata metadata = new ExtendedMetadata();
        metadata.setIdpDiscoveryEnabled(true);
        metadata.setIdpDiscoveryURL("test.fi/idpDisco/");
        context.setLocalExtendedMetadata(metadata);
        context.setLocalEntityId("localId");

        context.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        context.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));

        replayMock();
        entryPoint.initializeDiscovery(context);
        verifyMock();

    }

    /**
     * Test verifies initial values returned from getProfileOptions, when no customization is in place.
     *
     * @throws Exception error
     */
    @Test
    public void testInitialProfileOptions() throws Exception {

        WebSSOProfileOptions ssoProfileOptions = entryPoint.getProfileOptions(new SAMLMessageContext(), null);
        assertEquals(new Integer(2), ssoProfileOptions.getProxyCount());
        assertTrue(ssoProfileOptions.isIncludeScoping());
        assertFalse(ssoProfileOptions.getForceAuthN());
        assertFalse(ssoProfileOptions.getPassive());
        assertNull(ssoProfileOptions.getBinding());

    }

    /**
     * Test verifies that values returned from getProfileOptions can be customized.
     *
     * @throws Exception error
     */
    @Test
    public void testDefaultProfileOptions() throws Exception {

        expect(request.getParameter("idp")).andReturn("http://localhost:8080/opensso").anyTimes();
        replayMock();

        WebSSOProfileOptions defaultOptions = new WebSSOProfileOptions();
        defaultOptions.setProxyCount(0);
        defaultOptions.setIncludeScoping(false);
        defaultOptions.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        // Set default values
        entryPoint.setDefaultProfileOptions(defaultOptions);

        // Check that default values are used
        WebSSOProfileOptions ssoProfileOptions = entryPoint.getProfileOptions(new SAMLMessageContext(), null);
        assertEquals(new Integer(0), ssoProfileOptions.getProxyCount());
        assertFalse(ssoProfileOptions.isIncludeScoping());
        assertFalse(ssoProfileOptions.getForceAuthN());
        assertFalse(ssoProfileOptions.getPassive());
        assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, ssoProfileOptions.getBinding());

        // Check that value can't be altered after being set
        defaultOptions.setIncludeScoping(true);
        ssoProfileOptions = entryPoint.getProfileOptions(new SAMLMessageContext(), null);
        assertFalse(ssoProfileOptions.isIncludeScoping());

        // Check that default values can be cleared
        entryPoint.setDefaultProfileOptions(null);
        ssoProfileOptions = entryPoint.getProfileOptions(new SAMLMessageContext(), null);
        assertTrue(ssoProfileOptions.isIncludeScoping());        

        verifyMock();

    }

    /**
     * Verifies that entryPoint fails when invalid IDP is attempted.
     *
     * @throws Exception error
     */
    @Test(expected = ServletException.class)
    public void testInvalidIDP() throws Exception {

        expect(request.getSession(true)).andReturn(session);
        expect(request.getParameter(SAMLEntryPoint.DISCOVERY_RESPONSE_PARAMETER)).andReturn("false");

        SAMLTestHelper.setLocalContextParameters(request, "/samlApp", null);
        SAMLTestHelper.setPeerContextParameters(request, "testIDP", null);
        expect(request.getAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_CONTEXT_PATH)).andReturn("/samlApp");

        expect(request.getHeader("Accept")).andReturn(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        expect(request.getHeader(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_HEADER)).andReturn(null);
        replayMock();
        entryPoint.commence(request, response, null);
        verifyMock();
    }

    /**
     * Verifies that entryPoint fails when invalid IDP is attempted.
     *
     * @throws Exception error
     */
    @Test
    public void testCorrectIDP() throws Exception {

        expect(request.getSession(true)).andReturn(session);

        SAMLTestHelper.setLocalContextParameters(request, "/samlApp", null);
        SAMLTestHelper.setPeerContextParameters(request, "http://localhost:8080/opensso", null);

        expect(request.getHeader("Accept")).andReturn("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        expect(request.getHeader(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_HEADER)).andReturn(null);

        ssoProfile.sendAuthenticationRequest((SAMLMessageContext) notNull(), (WebSSOProfileOptions) notNull());

        replayMock();
        entryPoint.commence(request, response, null);
        verifyMock();

    }

    /**
     * Test check on whether request supports ECP - it doesn't in this case.
     *
     * @throws Exception error
     */
    @Test
    public void testECPRequest_no() throws Exception {

        expect(request.getHeader("Accept")).andReturn(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        expect(request.getHeader(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_HEADER)).andReturn(null);

        replayMock();
        assertFalse(SAMLUtil.isECPRequest(request));
        verifyMock();

    }

    /**
     * Test check on whether request supports ECP - it doesn in this case.
     *
     * @throws Exception error
     */
    @Test
    public void testECPRequest_yes() throws Exception {

        expect(request.getHeader("Accept")).andReturn("text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5, application/vnd.paos+xml");
        expect(request.getHeader(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_HEADER)).andReturn("ver='urn:liberty:paos:2003-08'; 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp'");

        replayMock();
        assertTrue(SAMLUtil.isECPRequest(request));
        verifyMock();

    }

    private void replayMock() {
        replay(ssoProfile);
        replay(request);
        replay(response);
        replay(session);
        replay(servletContext);
    }

    private void verifyMock() {
        verify(session);
        verify(response);
        verify(request);
        verify(ssoProfile);
        verify(servletContext);
    }

}