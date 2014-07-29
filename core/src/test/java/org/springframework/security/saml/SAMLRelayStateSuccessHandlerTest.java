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

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;

import static org.easymock.EasyMock.*;

/**
 * @author Michael Beauregard
 */
public class SAMLRelayStateSuccessHandlerTest {

    SAMLRelayStateSuccessHandler successHandler;
    Authentication authentication;
    SAMLCredential credential;
    HttpServletRequest request;
    HttpServletResponse response;
    RedirectStrategy redirectStrategy;

    @Before
    public void initialize() throws Exception {
        request = createMock(HttpServletRequest.class);
        response = createMock(HttpServletResponse.class);

        authentication = createMock(Authentication.class);

        NameIDBuilder nameIDBuilder = new NameIDBuilder();
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        List<Attribute> attrs = Collections.emptyList();

        credential = new SAMLCredential(
                nameIDBuilder.buildObject("uri:the-namespace", "localName", "prefix"),
                assertionBuilder.buildObject("uri:the-namespace", "localName", "prefix"),
                "remoteEntityID", "relayState", attrs, "localEntityID");

        redirectStrategy = createMock(RedirectStrategy.class);

        successHandler = new SAMLRelayStateSuccessHandler();
        successHandler.setRedirectStrategy(redirectStrategy);
    }

    /**
     * Verifies that the success handler interprets the RelayState in the SAMLCredential
     * as a redirect URL.
     * @throws Exception -
     */
    @Test
    public void testSuccessWithSAMLCredential() throws Exception {
        expect(authentication.getCredentials()).andReturn(credential);
        redirectStrategy.sendRedirect(request, response, credential.getRelayState());
        expectLastCall();

        replayMock();
        successHandler.onAuthenticationSuccess(request, response, authentication);
        verifyMock();
    }

    private void replayMock() {
        replay(request);
        replay(response);
        replay(authentication);
        replay(redirectStrategy);
    }

    private void verifyMock() {
        verify(request);
        verify(response);
        verify(authentication);
        verify(redirectStrategy);
    }
}
