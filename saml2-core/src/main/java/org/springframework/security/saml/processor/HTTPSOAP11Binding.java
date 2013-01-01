/* Copyright 2010 Mandus Elfving
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

import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11DecoderImpl;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Http SOAP 1.1 binding.
 *
 * @author Mandus Elfving, Vladimir Schaefer
 */
public class HTTPSOAP11Binding extends SAMLBindingImpl {

    /**
     * Creates binding with default encoder and decoder.
     *
     * @param parserPool parser pool
     */
    public HTTPSOAP11Binding(ParserPool parserPool) {
        this(new HTTPSOAP11DecoderImpl(parserPool), new HTTPSOAP11Encoder());
    }

    /**
     * Constructor with customized encoder and decoder
     *
     * @param decoder decoder
     * @param encoder encoder
     */
    public HTTPSOAP11Binding(MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
    }

    public boolean supports(InTransport transport) {
        if (transport instanceof HttpServletRequestAdapter) {
            HttpServletRequestAdapter t = (HttpServletRequestAdapter) transport;
            HttpServletRequest request = t.getWrappedRequest();
            return "POST".equalsIgnoreCase(t.getHTTPMethod()) && request.getContentType() != null && request.getContentType().startsWith("text/xml");
        } else {
            return false;
        }
    }

    public boolean supports(OutTransport transport) {
        return transport instanceof HTTPOutTransport;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_SOAP11_BINDING_URI;
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));

    }

}