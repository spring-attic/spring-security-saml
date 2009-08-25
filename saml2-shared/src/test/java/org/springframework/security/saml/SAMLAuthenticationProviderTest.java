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

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static org.easymock.EasyMock.*;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.userdetails.User;

/**
 * @author Vladimir Schäfer
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
        provider = new SAMLAuthenticationProvider(consumer);
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
     * Verifies that auhentication process passess sucesfully if input is correct.
     * @throws Exception error
     */
    @Test
    public void testAuthenticate() throws Exception {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();

        SAMLAuthenticationToken token = new SAMLAuthenticationToken(context, messageStorage);
        SAMLMessageStorage store = token.getMessageStore();
        SAMLCredential result = new SAMLCredential(nameID, assertion, "IDP");

        expect(consumer.processResponse(context, store)).andReturn(result);
        expect(nameID.getValue()).andReturn("Name");

        replayMock();
        Authentication authentication = provider.authenticate(token);
        assertEquals("Name", authentication.getName());
        verifyMock();
    }

    /**
     * Verifies that user details are filled correctly if set
     * @throws Exception error
     */
    @Test
    public void testAuthenticateUserDetails() throws Exception {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();

        SAMLUserDetailsService details = createMock(SAMLUserDetailsService.class);
        provider.setUserDetails(details);

        SAMLAuthenticationToken token = new SAMLAuthenticationToken(context, messageStorage);
        SAMLMessageStorage store = token.getMessageStore();
        SAMLCredential result = new SAMLCredential(nameID, assertion, "IDP");

        expect(consumer.processResponse(context, store)).andReturn(result);
        expect(nameID.getValue()).andReturn("Name");
        expect(details.loadUserBySAML(result)).andReturn(new User("test", "test", true, true, true, true, new GrantedAuthority[] {}));

        replayMock();
        replay(details);
        Authentication authentication = provider.authenticate(token);
        assertEquals("Name", authentication.getName());
        assertNotNull(authentication.getDetails());
        verify(details);
        verifyMock();
    }

    /**
     * Verifies that upon SAMLException thrown from provider the provider will fail.
     * @throws Exception error
     */
    @Test(expected = AuthenticationServiceException.class)
    public void testAuthenticateException() throws Exception {
        BasicSAMLMessageContext context = new BasicSAMLMessageContext();

        SAMLAuthenticationToken token = new SAMLAuthenticationToken(context, messageStorage);
        SAMLMessageStorage store = token.getMessageStore();
        SAMLCredential result = new SAMLCredential(nameID, assertion, "IDP");

        expect(consumer.processResponse(context, store)).andThrow(new SAMLException("Error"));
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

