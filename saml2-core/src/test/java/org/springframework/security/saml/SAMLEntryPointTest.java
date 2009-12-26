/* Copyright 2009 Vladimir Schäfer
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

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletException;
import javax.servlet.RequestDispatcher;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;

/**
 */
public class SAMLEntryPointTest {

    ApplicationContext context;

    SAMLEntryPoint entryPoint;
    WebSSOProfile ssoProfile;

    HttpSession session;
    HttpServletRequest request;
    HttpServletResponse response;
    MetadataManager manager;

    @Before
    public void initialize() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        entryPoint = (SAMLEntryPoint) context.getBean("samlEntryPoint");
        ssoProfile = createMock(WebSSOProfile.class);

        entryPoint.setWebSSOprofile(ssoProfile);

        request = createMock(HttpServletRequest.class);
        response = createMock(HttpServletResponse.class);
        session = createMock(HttpSession.class);
    }

    @Test
    public void testInitial() {
        assertNull(entryPoint.getIdpSelectionPath());
        assertEquals(ssoProfile, entryPoint.getWebSSOprofile());
        assertEquals("/saml/login", entryPoint.getFilterSuffix());
    }

    /**
     * Verifies that URLs are accepted as expected
     */
    @Test
    public void testProcessFilter() {
        entryPoint.setFilterSuffix("/saml/sso");
        expect(request.getRequestURI()).andReturn("/web/saml/sso");
        expect(request.getRequestURI()).andReturn("/saml/sso");
        expect(request.getRequestURI()).andReturn("/saml");
        expect(request.getRequestURI()).andReturn("/sso/");
        expect(request.getRequestURI()).andReturn("/saml/sso/");

        replayMock();
        assertTrue(entryPoint.processFilter(request));
        assertTrue(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        assertFalse(entryPoint.processFilter(request));
        verifyMock();
    }

    /**
     * Verifies that if no alternative filter suffix is set the value "/saml/login" is used.
     */
    @Test
    public void testProcessFilterDefault() {
        entryPoint.setFilterSuffix(null);
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
     * Verifies that entry point will redirect user to IDP selection if login parameter is not
     * set to true and idpSelectionPath is set.
     * @throws Exception error
     */
    @Test
    public void testIDPSelection() throws Exception {

        RequestDispatcher dispatcher = createMock(RequestDispatcher.class);

        entryPoint.setIdpSelectionPath("/selectIDP");
        expect(request.getParameter(SAMLEntryPoint.LOGIN_PARAMETER)).andReturn("false");
        expect(request.getRequestDispatcher("/selectIDP")).andReturn(dispatcher);
        dispatcher.include(request, response);

        replay(dispatcher);
        replayMock();
        entryPoint.commence(request, response, null);
        verifyMock();
        verify(dispatcher);
    }

    /**
     * Verifies that entryPoint fails when invalid IDP is attempted.
     * @throws Exception error
     */
    @Test(expected = ServletException.class)
    public void testInvalidIDP() throws Exception {
        entryPoint.setIdpSelectionPath(null);

        expect(request.getSession(true)).andReturn(session);
        expect(session.getAttribute("_springSamlStorageKey")).andReturn(null);
        expect(session.getAttribute("_springSamlStorageKey")).andReturn(null);
        session.setAttribute(eq("_springSamlStorageKey"), notNull());
        expect(request.getParameter("idp")).andReturn("testIDP");

        replayMock();
        entryPoint.commence(request, response, null);
        verifyMock();
    }

    /**
     * Verifies that entryPoint fails when invalid IDP is attempted.
     * @throws Exception error
     */
    @Test
    public void testCorrectIDP() throws Exception {
        entryPoint.setIdpSelectionPath(null);

        expect(request.getSession(true)).andReturn(session);
        expect(session.getAttribute("_springSamlStorageKey")).andReturn(null);
        expect(session.getAttribute("_springSamlStorageKey")).andReturn(null);
        session.setAttribute(eq("_springSamlStorageKey"), notNull());
        expect(request.getParameter("idp")).andReturn("http://localhost:8080/opensso");
        expect(ssoProfile.initializeSSO((WebSSOProfileOptions) notNull(), (SAMLMessageStorage) notNull(), eq(request), eq(response))).andReturn(null);

        replayMock();
        entryPoint.commence(request, response, null);
        verifyMock();
    }

    /**
     * Verfies that mising web profile fails whole operation. 
     * @throws Exception error
     */
    @Test(expected = ServletException.class)
    public void testMissingWebProfile() throws Exception {
        entryPoint.setWebSSOprofile(null);
        entryPoint.commence(request, response, null);
    }

    /**
     * Verfies that mising metadataManager fails whole operation.
     * @throws Exception error
     */
    @Test(expected = ServletException.class)
    public void testMissingMetadataManager() throws Exception {
        entryPoint.setMetadata(null);
        entryPoint.commence(request, response, null);
    }

    private void replayMock() {
        replay(ssoProfile);
        replay(request);
        replay(response);
        replay(session);
    }

    private void verifyMock() {
        verify(session);
        verify(response);
        verify(request);
        verify(ssoProfile);
    }

}