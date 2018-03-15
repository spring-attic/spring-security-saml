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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DataTypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML 2.0 HTTP Redirect decoder using the DEFLATE encoding method.
 *
 * This decoder only supports DEFLATE compression.
 */
public class HTTPRedirectDeflateDecoder extends BaseSAML2MessageDecoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPRedirectDeflateDecoder.class);

    /** Constructor. */
    public HTTPRedirectDeflateDecoder() {
        super();
    }

    /**
     * Constructor.
     *
     * @param pool parser pool used to deserialize messages
     */
    public HTTPRedirectDeflateDecoder(ParserPool pool) {
        super(pool);
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
    }

    /** {@inheritDoc} */
    protected boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx) {
        return isMessageSigned(samlMsgCtx);
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
        String relayState = inTransport.getParameterValue("RelayState");
        samlMsgCtx.setRelayState(relayState);
        log.debug("Decoded RelayState: {}", relayState);

        InputStream samlMessageIns;
        if (!DataTypeHelper.isEmpty(inTransport.getParameterValue("SAMLRequest"))) {
            samlMessageIns = decodeMessage(inTransport.getParameterValue("SAMLRequest"));
        } else if (!DataTypeHelper.isEmpty(inTransport.getParameterValue("SAMLResponse"))) {
            samlMessageIns = decodeMessage(inTransport.getParameterValue("SAMLResponse"));
        } else {
            throw new MessageDecodingException(
                    "No SAMLRequest or SAMLResponse query path parameter, invalid SAML 2 HTTP Redirect message");
        }

        SAMLObject samlMessage = (SAMLObject) unmarshallMessage(samlMessageIns);
        samlMsgCtx.setInboundSAMLMessage(samlMessage);
        samlMsgCtx.setInboundMessage(samlMessage);
        log.debug("Decoded SAML message");

        populateMessageContext(samlMsgCtx);
    }

    /** {@inheritDoc} */
    protected boolean isMessageSigned(SAMLMessageContext messageContext) {
        HTTPInTransport inTransport = (HTTPInTransport) messageContext.getInboundMessageTransport();
        String sigParam = inTransport.getParameterValue("Signature");
        return (!DataTypeHelper.isEmpty(sigParam)) || super.isMessageSigned(messageContext);
    }

    /**
     * Base64 decodes the SAML message and then decompresses the message.
     *
     * @param message Base64 encoded, DEFALTE compressed, SAML message
     *
     * @return the SAML message
     *
     * @throws MessageDecodingException thrown if the message can not be decoded
     */
    protected InputStream decodeMessage(String message) throws MessageDecodingException {
        log.debug("Base64 decoding and inflating SAML message");

        byte[] decodedBytes = Base64.decode(message);
        if(decodedBytes == null){
            log.error("Unable to Base64 decode incoming message");
            throw new MessageDecodingException("Unable to Base64 decode incoming message");
        }

        try {
            ByteArrayInputStream bytesIn = new ByteArrayInputStream(decodedBytes);
            InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater(true));
            return inflater;
        } catch (Exception e) {
            log.error("Unable to Base64 decode and inflate SAML message", e);
            throw new MessageDecodingException("Unable to Base64 decode and inflate SAML message", e);
        }
    }
}