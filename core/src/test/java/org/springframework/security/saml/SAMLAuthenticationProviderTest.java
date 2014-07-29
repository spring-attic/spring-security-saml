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

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.NameID;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLEmptyLogger;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;

import java.util.Arrays;
import java.util.LinkedList;

import static junit.framework.Assert.*;
import static org.easymock.EasyMock.*;

/**
 * @author Vladimir Schafer
 */
public class SAMLAuthenticationProviderTest {

    WebSSOProfileConsumer consumer;
    SAMLAuthenticationProvider provider;
    SAMLMessageStorage messageStorage;
    NameID nameID;
    Assertion assertion;

    @Before
    public void initialize() {
        consumer = createMock(WebSSOProfileConsumer.class);
        provider = new SAMLAuthenticationProvider();
        provider.setConsumer(consumer);
        provider.setForcePrincipalAsString(true);
        provider.setSamlLogger(new SAMLEmptyLogger());
        messageStorage = createMock(SAMLMessageStorage.class);
        nameID = createMock(NameID.class);
        assertion = createMock(Assertion.class);
    }

    /**
     * Verifies that unsupported Authentication object will be rejected.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testInvalidAuthenticationObject() {
        Authentication auth = new UsernamePasswordAuthenticationToken("user", "pass");
        provider.authenticate(auth);
    }

    /**
     * Verifies that authentication process passes successfully if input is correct.
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticate() throws Exception {
        SAMLMessageContext context = new SAMLMessageContext();
        context.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);

        SAMLAuthenticationToken token = new SAMLAuthenticationToken(context);
        SAMLCredential result = new SAMLCredential(nameID, assertion, "IDP", "testSP");

        expect(consumer.processAuthenticationResponse(context)).andReturn(result);
        expect(nameID.getValue()).andReturn("Name");

        DateTime expiry = new DateTime().plusHours(4);
        AuthnStatement as = createMock(AuthnStatement.class);
        expect(assertion.getAuthnStatements()).andReturn(Arrays.asList(as)).anyTimes();
        expect(as.getSessionNotOnOrAfter()).andReturn(expiry);

        replay(as);
        replayMock();
        Authentication authentication = provider.authenticate(token);
        assertEquals("Name", authentication.getName());
        assertTrue(authentication instanceof ExpiringUsernameAuthenticationToken);

        ExpiringUsernameAuthenticationToken t = (ExpiringUsernameAuthenticationToken) authentication;
        assertEquals(expiry.toDate(), t.getTokenExpiration());

        verifyMock();
        verify(as);
    }

    /**
     * Verifies that user details are filled correctly if set and that entitlements of the user returned from
     * the userDetails are set to the authentication object.
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticateUserDetails() throws Exception {
        SAMLMessageContext context = new SAMLMessageContext();
        context.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);

        SAMLUserDetailsService details = createMock(SAMLUserDetailsService.class);
        provider.setUserDetails(details);

        SAMLAuthenticationToken token = new SAMLAuthenticationToken(context);
        SAMLCredential result = new SAMLCredential(nameID, assertion, "IDP", "localSP");

        expect(consumer.processAuthenticationResponse(context)).andReturn(result);
        expect(assertion.getAuthnStatements()).andReturn(new LinkedList<AuthnStatement>());
        User user = new User("test", "test", true, true, true, true, Arrays.asList(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2")));
        expect(details.loadUserBySAML(result)).andReturn(user);

        provider.setForcePrincipalAsString(false);

        replayMock();
        replay(details);
        Authentication authentication = provider.authenticate(token);
        assertEquals(user, authentication.getPrincipal());
        assertEquals(user.getUsername(), authentication.getName());
        assertNotNull(authentication.getDetails());
        assertEquals(2, authentication.getAuthorities().size());
        assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("role1")));
        assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("role2")));
        verify(details);
        verifyMock();
    }

    /**
     * Verifies that upon SAMLException thrown from provider the provider will fail.
     *
     * @throws Exception error
     */
    @Test(expected = AuthenticationServiceException.class)
    public void testAuthenticateException() throws Exception {
        SAMLMessageContext context = new SAMLMessageContext();

        SAMLAuthenticationToken token = new SAMLAuthenticationToken(context);
        SAMLCredential result = new SAMLCredential(nameID, assertion, "IDP", "localSP");

        expect(consumer.processAuthenticationResponse(context)).andThrow(new SAMLException("Error"));
        expect(nameID.getValue()).andReturn("Name");

        replayMock();
        provider.authenticate(token);
        verifyMock();
    }

    private void replayMock() {
        replay(consumer);
        replay(messageStorage);
        replay(nameID);
        replay(assertion);
    }

    private void verifyMock() {
        verify(consumer);
        verify(messageStorage);
        verify(nameID);
        verify(assertion);
    }
}