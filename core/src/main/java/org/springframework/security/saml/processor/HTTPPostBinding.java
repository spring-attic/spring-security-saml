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

import java.util.List;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.compat.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.compat.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.compat.security.SecurityPolicyRule;
import org.opensaml.compat.transport.InTransport;
import org.opensaml.compat.transport.OutTransport;
import org.opensaml.compat.transport.http.HTTPInTransport;
import org.opensaml.compat.transport.http.HTTPOutTransport;
import org.opensaml.compat.transport.http.HTTPTransport;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;


/**
 * Http POST binding.
 *
 * @author Mandus Elfving
 */
public class HTTPPostBinding extends SAMLBindingImpl {

    /**
     * Pool for message deserializers.
     */
    protected ParserPool parserPool;

    /**
     * Creates default implementation of the binding.
     *
     * @param parserPool     parserPool for message deserialization
     * @param velocityEngine engine for message formatting
     */
    public HTTPPostBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        super(new HTTPPostDecoder(), new HTTPPostEncoder());
        HTTPPostDecoder decoder = (HTTPPostDecoder) getMessageDecoder();
        decoder.setParserPool(parserPool);
        HTTPPostEncoder encoder = (HTTPPostEncoder) getMessageEncoder();
        encoder.setVelocityEngine(velocityEngine);
        encoder.setVelocityTemplateId("/templates/saml2-post-binding.vm");
        this.parserPool = parserPool;
    }

    /**
     * Implementation of the binding with custom encoder and decoder.
     *
     * @param parserPool     parserPool for message deserialization
     * @param decoder custom decoder implementation
     * @param encoder custom encoder implementation
     */
    public HTTPPostBinding(ParserPool parserPool, MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
        this.parserPool = parserPool;
    }

    public boolean supports(InTransport transport) {
        if (transport instanceof HTTPInTransport) {
            HTTPTransport t = (HTTPTransport) transport;
            return "POST".equalsIgnoreCase(t.getHTTPMethod()) && (t.getParameterValue("SAMLRequest") != null || t.getParameterValue("SAMLResponse") != null);
        } else {
            return false;
        }
    }

    public boolean supports(OutTransport transport) {
        return transport instanceof HTTPOutTransport;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        securityPolicy.add(new SAML2HTTPPostSimpleSignRule(engine, parserPool, engine.getKeyInfoResolver()));
        securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));

    }

}