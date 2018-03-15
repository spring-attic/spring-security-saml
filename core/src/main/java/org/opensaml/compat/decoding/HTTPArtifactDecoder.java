/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat.decoding;


import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.DataTypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML 2 Artifact Binding decoder, support both HTTP GET and POST.
 *
 * <strong>NOTE: This decoder is not yet implemented.</strong>
 * */
public class HTTPArtifactDecoder extends BaseSAML2MessageDecoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPArtifactDecoder.class);

    /**
     * Constructor.
     *
     * @param pool parser pool used to deserialize messages
     */
    public HTTPArtifactDecoder(ParserPool pool) {
        super(pool);
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    /** {@inheritDoc} */
    protected boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx) {
        return false;
    }

    /** {@inheritDoc} */
    protected String getIntendedDestinationEndpointURI(SAMLMessageContext samlMsgCtx) throws MessageDecodingException {
        // Not relevant in this binding/profile, there is neither SAML message
        // nor binding parameter with this information
        return null;
    }

    /** {@inheritDoc} */
    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this decoder only support SAMLMessageContext");
            throw new MessageDecodingException(
                    "Invalid message context type, this decoder only support SAMLMessageContext");
        }

        if (!(messageContext.getInboundMessageTransport() instanceof HTTPInTransport)) {
            log.error("Invalid inbound message transport type, this decoder only support HTTPInTransport");
            throw new MessageDecodingException(
                    "Invalid inbound message transport type, this decoder only support HTTPInTransport");
        }

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

        HTTPInTransport inTransport = (HTTPInTransport) samlMsgCtx.getInboundMessageTransport();
        String relayState = DataTypeHelper.safeTrim(inTransport.getParameterValue("RelayState"));
        samlMsgCtx.setRelayState(relayState);

        processArtifact(samlMsgCtx);

        populateMessageContext(samlMsgCtx);
    }

    /**
     * Process the incoming artifact by decoding the artifacts, dereferencing it from the artifact issuer and
     * storing the resulting protocol message in the message context.
     *
     * @param samlMsgCtx current message context
     *
     * @throws MessageDecodingException thrown if there is a problem decoding or dereferencing the artifact
     */
    protected void processArtifact(SAMLMessageContext samlMsgCtx) throws MessageDecodingException {
        HTTPInTransport inTransport = (HTTPInTransport) samlMsgCtx.getInboundMessageTransport();
        String encodedArtifact = DataTypeHelper.safeTrimOrNullString(inTransport.getParameterValue("SAMLart"));
        if (encodedArtifact == null) {
            log.error("URL SAMLart parameter was missing or did not contain a value.");
            throw new MessageDecodingException("URL TARGET parameter was missing or did not contain a value.");
        }

        // TODO decode artifact; resolve issuer resolution endpoint; dereference using ArtifactResolve
        // over synchronous backchannel binding; store resultant protocol message as the inbound SAML message.
    }
}