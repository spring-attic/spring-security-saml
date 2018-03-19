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

import javax.servlet.http.HttpServletRequest;
import java.net.URL;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.compat.Base64;
import org.opensaml.compat.transport.http.HttpServletRequestAdapter;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLTestHelper;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;

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

    public static String encodeFromFile( String filename )
    {
        String encodedData = null;
        Base64.InputStream bis = null;
        try
        {
            // Set up some useful variables
            java.io.File file = new java.io.File( filename );
            byte[] buffer = new byte[ Math.max((int)(file.length() * 1.4),40) ]; // Need max() for math on small files (v2.2.1)
            int length   = 0;
            int numBytes = 0;

            // Open a stream
            bis = new Base64.InputStream(
                new java.io.BufferedInputStream(
                    new java.io.FileInputStream( file ) ), Base64.ENCODE );

            // Read until done
            while( ( numBytes = bis.read( buffer, length, 4096 ) ) >= 0 )
                length += numBytes;

            // Save in a variable to return
            encodedData = new String( buffer, 0, length, Base64.PREFERRED_ENCODING );

        }   // end try
        catch( java.io.IOException e )
        {
            throw new RuntimeException(e);
        }   // end catch: IOException
        finally
        {
            try{ bis.close(); } catch( Exception e) {}
        }   // end finally

        return encodedData;
    }   // end encodeFromFile

    private void replayMock() {
        replay(request);
    }

    private void verifyMock() {
        verify(request);
        reset(request);
    }
}