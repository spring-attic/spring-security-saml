/*
 * Copyright 2010 Jonathan Tellier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Test case for {@link HTTPPAOS11Decoder}. Note that only the few functionalities added
 * on top of {@link HTTPSOAP11Decoder} are tested.
 */
package org.opensaml.liberty.binding.decoding;

import javax.xml.namespace.QName;

import org.opensaml.common.BaseTestCase;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.context.SAMLMessageContext;

public class HTTPPAOS11DecoderTest extends BaseTestCase {
    
    private HTTPPAOS11Decoder decoder;
    private SAMLMessageContext messageContext;
    private MockHttpServletRequest httpRequest;
    
    private String expectedRelayState;
    
    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        
        expectedRelayState = "df558a";
        
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod("POST");
        
        messageContext = new SAMLMessageContext();
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));
        
        decoder = new HTTPPAOS11Decoder();
    }
    
    public void testUnderstandsPaosResponseHeader() {
        QName paosResponseHeader = new QName(SAMLConstants.PAOS_NS, "Response",
                SAMLConstants.PAOS_PREFIX);
        
        assertTrue("The PAOS Decoder does not understand paos:Response header",
                decoder.getUnderstoodHeaders().contains(paosResponseHeader));
    }
    
    public void testRelayState() throws MessageDecodingException, SecurityException {
        String soapMessage =
            "<soap11:Envelope xmlns:soap11=\"http://schemas.xmlsoap.org/soap/envelope/\"> " +
            "<soap11:Header> " +
                "<ecp:RelayState " +
                    "xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" " +
                    "soap11:actor=\"http://schemas.xmlsoap.org/soap/actor/next/\" " +
                    "soap11:mustUnderstand=\"1\">" + expectedRelayState +
                "</ecp:RelayState></soap11:Header>" +
            "<soap11:Body> " +
                "<samlp:Response ID=\"foo\" IssueInstant=\"1970-01-01T00:00:00.000Z\" " +
                "Version=\"2.0\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"> " +
                "<samlp:Status><samlp:StatusCode " +
                "Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/> " +
                "</samlp:Status></samlp:Response>" + 
            "</soap11:Body></soap11:Envelope>";
            
        httpRequest.setContent(soapMessage.getBytes());
    
        decoder.decode(messageContext);
        
        assertEquals("The messageContext does not have the correct RelayState",
                expectedRelayState, messageContext.getRelayState());        
    }

}
