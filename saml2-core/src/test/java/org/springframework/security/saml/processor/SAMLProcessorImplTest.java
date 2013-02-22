/* Copyright 2009 Vladimir Schaefer
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
package org.springframework.security.saml.processor;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.Base64;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLTestHelper;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;

import static junit.framework.Assert.*;
import static org.easymock.EasyMock.*;

/**
 * @author Vladimir Schaefer
 */
public class SAMLProcessorImplTest {

    ApplicationContext context;
    SAMLProcessorImpl processor;
    SAMLMessageContext samlContext;
    HttpServletRequest request;

    @Before
    public void initialize() throws Exception {

        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        processor = context.getBean("processor", SAMLProcessorImpl.class);

        request = createMock(HttpServletRequest.class);

        SAMLTestHelper.setLocalContextParameters(request, "/", null);

        replayMock();
        SAMLContextProvider contextProvider = context.getBean("contextProvider", SAMLContextProvider.class);
        samlContext = contextProvider.getLocalEntity(request, null);
        verifyMock();

    }

    /**
     * Verifies that message sent using POST binding is correctly parsed from HttpRequest data.
     *
     * @throws Exception error
     */
    @Test
    public void testPOSTResponseParsing() throws Exception {

        prepareHttpRequest("message/SAMLResponse.xml", "POST", "http://localhost:8080/spring-security-saml2-webapp/saml/SSO", "text/html");
        replayMock();
        SAMLMessageContext context = processor.retrieveMessage(samlContext);
        verifyMock();

        assertNotNull(context.getInboundSAMLMessage());
        assertTrue(context.getInboundSAMLMessage() instanceof Response);
        assertEquals("s22520705f2c89536ee66a2c4c92f2832ce9cdc019", context.getInboundSAMLMessageId());
        assertEquals("http://localhost:8080/opensso", context.getPeerEntityId());
    }

    /**
     * Verifies that message sent to different URL than received at will be rejected.
     *
     * @throws Exception error
     */
    @Test(expected = SecurityException.class)
    public void testMessageRecipientInvalid() throws Exception {
        prepareHttpRequest("message/SAMLResponse.xml", "POST", "http://localhost:8080/unexpectedURL", "text/html");
        replayMock();
        processor.retrieveMessage(samlContext);
        verifyMock();
    }

    /**
     * Verifies that decoder for messages sent using GET method is available.
     *
     * @throws Exception error
     */
    @Test
    public void testGETDecoder() throws Exception {
        prepareHttpRequest("message/SAMLResponse.xml", "GET", "http://localhost:8080/url", "text/html");
        replayMock();
        MessageDecoder decoder = processor.getBinding(new HttpServletRequestAdapter(request)).getMessageDecoder();
        verifyMock();
        assertNotNull(decoder);
    }

    /**
     * Verifies that message sent with unknown binding will be rejected..
     *
     * @throws Exception error
     */
    @Test(expected = SAMLException.class)
    public void testUnknownDecoder() throws Exception {
        prepareHttpRequest("message/SAMLResponse.xml", "HEAD", "http://localhost:8080/url", "application/json");
        replayMock();
        MessageDecoder decoder = processor.getBinding(new HttpServletRequestAdapter(request)).getMessageDecoder();
        verifyMock();
        assertNotNull(decoder);
    }

    /**
     * Verifies that message sent to different URL than received at will be rejected.
     *
     * @throws Exception error
     */
    @Test(expected = SecurityException.class)
    public void testMessageInvalidSignature() throws Exception {
        prepareHttpRequest("message/SAMLResponseInvalidSignature.xml", "POST", "http://localhost:8081/spring-security-saml2-webapp/saml/SSO", "text/html");
        replayMock();
        processor.retrieveMessage(samlContext);
        verifyMock();
    }

    protected void prepareHttpRequest(String messageFile, String method, String url, String contentType) throws Exception {
        URL urlP = new URL(url);
        String fileName = context.getResource(messageFile).getFile().getPath();
        String message = Base64.encodeFromFile(fileName);
        expect(request.getMethod()).andReturn(method).anyTimes();
        expect(request.getContentLength()).andReturn(message.length()).anyTimes();
        expect(request.getContentType()).andReturn(contentType).anyTimes();
        expect(request.getParameter("SAMLart")).andReturn(null).anyTimes();
        expect(request.getParameter("SAMLRequest")).andReturn(null).anyTimes();
        expect(request.getParameter("SAMLResponse")).andReturn(message).anyTimes();
        expect(request.getParameter("RelayState")).andReturn("").anyTimes();
        expect(request.getParameter("Signature")).andReturn("").anyTimes();
        expect(request.getRequestURI()).andReturn(urlP.getPath()).anyTimes();
        expect(request.getRequestURL()).andReturn(new StringBuffer(url)).anyTimes();
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null).anyTimes();
        expect(request.isSecure()).andReturn(false).anyTimes();
        expect(request.getAttribute(SAMLConstants.LOCAL_ENTITY_ID)).andReturn(null).anyTimes();
    }

    private void replayMock() {
        replay(request);
    }

    private void verifyMock() {
        verify(request);
        reset(request);
    }
}