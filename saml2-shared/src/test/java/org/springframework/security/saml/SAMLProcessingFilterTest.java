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
import static org.easymock.EasyMock.*;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.processor.SAMLProcessor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Hashtable;

/**
 * @author Vladimir Schäfer
 */
public class SAMLProcessingFilterTest {

    SAMLProcessingFilter processingFiler;
    SAMLProcessor processor;
    HttpServletRequest request;
    HttpSession session;

    @Before
    public void initialize() {
        processingFiler = new SAMLProcessingFilter();
        processor = createMock(SAMLProcessor.class);
        processingFiler.setSAMLProcessor(processor);
        request = createMock(HttpServletRequest.class);
        session = createMock(HttpSession.class);
    }

    /**
     * Verfifies that the SAMLProcessor collaborator must be set, otherwise exception is thrown
     */
    @Test(expected = SAMLRuntimeException.class)
    public void testMissingProcessor() {
        processingFiler.setSAMLProcessor(null);
        replayMock();
        processingFiler.attemptAuthentication(request, null);
        verifyMock();
    }

    /**
     * Verifies that error during processing results in error of whole authentication.
     * @throws Exception error
     */
    @Test(expected = SAMLRuntimeException.class)
    public void testErrorDuringProcessing() throws Exception {
        expect(processor.processSSO(request)).andThrow(new SAMLException("Processing error"));
        replayMock();
        processingFiler.attemptAuthentication(request, null);
        verifyMock();
    }

    @Test
    public void testDefaultURL() {
        assertEquals("/saml/SSO", processingFiler.getFilterProcessesUrl());
    }

    /**
     * Verifies correct pass through the processing filter - process the request, create
     * SAML authntication token and pass it to the authentication manager.
     * @throws Exception error
     */
    @Test
    public void testCorrectPass() throws Exception {

        Authentication token = new UsernamePasswordAuthenticationToken("user", "pass");
        AuthenticationManager manager = createMock(AuthenticationManager.class);
        processingFiler.setAuthenticationManager(manager);

        expect(processor.processSSO(request)).andReturn(new BasicSAMLMessageContext());
        expect(manager.authenticate((Authentication) notNull())).andReturn(token);
        expect(request.getSession(true)).andReturn(session);
        expect(session.getAttribute("_springSamlStorageKey")).andReturn(new Hashtable());

        replay(manager);
        replayMock();
        Authentication authentication = processingFiler.attemptAuthentication(request, null);
        assertEquals(token, authentication);
        verifyMock();
        verify(manager);
    }

    private void replayMock() {
        replay(session);
        replay(processor);
        replay(request);
    }

    private void verifyMock() {
        verify(request);
        verify(processor);
        verify(session);
    }

}