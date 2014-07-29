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

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPArtifactDecoderImpl;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;

import java.util.List;

/**
 * Http artifact binding.
 *
 * @author Mandus Elfving, Vladimir Schaefer
 */
public class HTTPArtifactBinding extends SAMLBindingImpl {

    /**
     * Creates default implementation of the binding.
     *
     * @param parserPool      parserPool for message deserialization
     * @param velocityEngine  engine for message formatting
     * @param artifactProfile profile used to retrieven the artifact message
     */
    public HTTPArtifactBinding(ParserPool parserPool, VelocityEngine velocityEngine, ArtifactResolutionProfile artifactProfile) {
        this(new HTTPArtifactDecoderImpl(artifactProfile, parserPool), new HTTPArtifactEncoder(velocityEngine, "/templates/saml2-post-artifact-binding.vm", null));
    }

    /**
     * Implementation of the binding with custom encoder and decoder.
     *
     * @param decoder custom decoder implementation
     * @param encoder custom encoder implementation
     */
    public HTTPArtifactBinding(MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
    }

    public boolean supports(InTransport transport) {
        if (transport instanceof HTTPInTransport) {
            HTTPInTransport t = (HTTPInTransport) transport;
            return t.getParameterValue("SAMLart") != null;
        } else {
            return false;
        }
    }

    public boolean supports(OutTransport transport) {
        return transport instanceof HTTPOutTransport;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));

    }

}