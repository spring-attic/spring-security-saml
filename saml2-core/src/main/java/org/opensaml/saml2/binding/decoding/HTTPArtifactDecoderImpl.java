/*
 * Copyright 2009 Mandus Elfving
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
package org.opensaml.saml2.binding.decoding;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;

/**
 * Class to decode HTTP artifact binding and request the SAML message through the artifact request
 * response protocol with an IDP. At the moment only supports GET requests.
 *
 * @author Mandus Elfving
 */
public class HTTPArtifactDecoderImpl extends BaseSAML2MessageDecoder {

    private final Logger log = LoggerFactory.getLogger(HTTPArtifactDecoderImpl.class);

    private ArtifactResolutionProfile resolutionProfile;

    public HTTPArtifactDecoderImpl(ArtifactResolutionProfile resolutionProfile, ParserPool parserPool) {
        super(parserPool);
        this.resolutionProfile = resolutionProfile;
    }

    @Override
    protected boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx) {
        return false;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    @Override
    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {

        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this decoder only support SAMLMessageContext");
            throw new MessageDecodingException(
                    "Invalid message context type, this decoder only support SAMLMessageContext");
        }

        org.springframework.security.saml.context.SAMLMessageContext samlMessageContext = (org.springframework.security.saml.context.SAMLMessageContext) messageContext;

        if (!(samlMessageContext.getInboundMessageTransport() instanceof HTTPInTransport)) {
            log.error("Invalid inbound message transport type, this decoder only support HTTPInTransport");
            throw new MessageDecodingException("Invalid inbound message transport type, this decoder only support HTTPInTransport");
        }

        HTTPInTransport inTransport = (HTTPInTransport) samlMessageContext.getInboundMessageTransport();
        HTTPOutTransport outTransport = (HTTPOutTransport) samlMessageContext.getOutboundMessageTransport();

        /*
         * Artifact parameter.
         */
        String artifactId = DatatypeHelper.safeTrimOrNullString(inTransport.getParameterValue("SAMLart"));
        if (artifactId == null) {
            log.error("SAMLart parameter was missing or did not contain a value.");
            throw new MessageDecodingException("SAMLArt parameter was missing or did not contain a value.");
        }

        log.debug("Artifact id: {}", artifactId);

        /*
         * Relay state parameter.
         */
        samlMessageContext.setRelayState(inTransport.getParameterValue("RelayState"));

        log.debug("Decoded RelayState: {}", samlMessageContext.getRelayState());

        SAMLObject message = resolutionProfile.resolveArtifact(samlMessageContext, artifactId, getActualReceiverEndpointURI(samlMessageContext));

        // Fix potentially overwritten transports and set constants
        samlMessageContext.setInboundSAMLMessage(message);
        samlMessageContext.setInboundMessageTransport(inTransport);
        samlMessageContext.setOutboundMessageTransport(outTransport);
        samlMessageContext.setInboundSAMLBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

        populateMessageContext(samlMessageContext);
        
    }

}