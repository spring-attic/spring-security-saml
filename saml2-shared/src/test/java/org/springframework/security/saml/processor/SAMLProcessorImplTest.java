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
package org.springframework.security.saml.processor;

import static junit.framework.Assert.*;
import static org.easymock.EasyMock.*;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.Base64;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;

/**
 * @author Vladimir Schäfer
 */
public class SAMLProcessorImplTest {

    ApplicationContext context;
    SAMLProcessorImpl processor;

    HttpServletRequest request;

    @Before
    public void initialize() {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        processor = (SAMLProcessorImpl) context.getBean("processor", SAMLProcessorImpl.class);
        request = createMock(HttpServletRequest.class);
    }

    /**
     * Verifies that message sent using POST binding is correctly parsed from HttpRequest data.
     *
     * @throws Exception error
     */
    @Test
    public void testPOSTResponseParsing() throws Exception {
        prepareHttpRequest("message/SAMLResponse.xml", "POST", "http://localhost:8080/spring-security-saml2-webapp/saml/SSO");
        replayMock();
        BasicSAMLMessageContext context = processor.processSSO(request);
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
    public void testMessageReceipientInvalid() throws Exception {
        prepareHttpRequest("message/SAMLResponse.xml", "POST", "http://localhost:8080/unexpectedURL");
        replayMock();
        processor.processSSO(request);
        verifyMock();
    }

    /**
     * Verifies that decoder for messages sent using GET method is available.
     *
     * @throws Exception error
     */
    @Test
    public void testGETDecoder() throws Exception {
        prepareHttpRequest("message/SAMLResponse.xml", "GET", "http://localhost:8080/url");
        replayMock();
        MessageDecoder decoder = processor.getDecoder(request, new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>());
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
        prepareHttpRequest("message/SAMLResponse.xml", "HEAD", "http://localhost:8080/url");
        replayMock();
        MessageDecoder decoder = processor.getDecoder(request, new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>());
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
        prepareHttpRequest("message/SAMLResponseInvalidSignature.xml", "POST", "http://localhost:8080/spring-security-saml2-webapp/saml/SSO");
        replayMock();
        processor.processSSO(request);
        verifyMock();
    }

    protected void prepareHttpRequest(String messageFile, String method, String url) throws Exception {
        URL urlP = new URL(url);
        String fileName = context.getResource(messageFile).getFile().getPath();
        String message = Base64.encodeFromFile(fileName);
        expect(request.getMethod()).andReturn(method).anyTimes();
        expect(request.getContentLength()).andReturn(message.length()).anyTimes();
        expect(request.getParameter("SAMLRequest")).andReturn(null).anyTimes();
        expect(request.getParameter("SAMLResponse")).andReturn(message).anyTimes();
        expect(request.getParameter("RelayState")).andReturn("").anyTimes();
        expect(request.getRequestURI()).andReturn(urlP.getPath()).anyTimes();
        expect(request.getRequestURL()).andReturn(new StringBuffer(url)).anyTimes();
    }

    private void replayMock() {
        replay(request);
    }

    private void verifyMock() {
        verify(request);
    }

}