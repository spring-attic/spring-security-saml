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

import javax.xml.namespace.QName;
import java.util.List;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.DataTypeHelper;
import org.opensaml.xml.util.LazyList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML 2.0 SOAP 1.1 over HTTP binding decoder.
 */
public class HTTPSOAP11Decoder extends BaseSAML2MessageDecoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPSOAP11Decoder.class);

    /** QNames of understood SOAP headers. */
    private List<QName> understoodHeaders;

    /** QName of SOAP mustUnderstand header attribute. */
    private final QName soapMustUnderstand = new QName(SAMLConstants.SOAP11ENV_NS, "mustUnderstand");

    /** Constructor. */
    public HTTPSOAP11Decoder() {
        super();
        understoodHeaders = new LazyList<QName>();
    }

    /**
     * Constructor.
     *
     * @param pool parser pool used to deserialize messages
     */
    public HTTPSOAP11Decoder(ParserPool pool) {
        super(pool);
        understoodHeaders = new LazyList<QName>();
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_SOAP11_BINDING_URI;
    }

    /** {@inheritDoc} */
    protected boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx) {
        return false;
    }

    /**
     * Gets the SOAP header names that are understood by the application.
     *
     * @return SOAP header names that are understood by the application
     */
    public List<QName> getUnderstoodHeaders() {
        return understoodHeaders;
    }

    /**
     * Sets the SOAP header names that are understood by the application.
     *
     * @param headerNames SOAP header names that are understood by the application
     */
    public void setUnderstoodHeaders(List<QName> headerNames) {
        understoodHeaders.clear();
        if (headerNames != null) {
            understoodHeaders.addAll(headerNames);
        }
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
        if (!inTransport.getHTTPMethod().equalsIgnoreCase("POST")) {
            throw new MessageDecodingException("This message decoder only supports the HTTP POST method");
        }

        log.debug("Unmarshalling SOAP message");
        Envelope soapMessage = (Envelope) unmarshallMessage(inTransport.getIncomingStream());
        samlMsgCtx.setInboundMessage(soapMessage);

        Header messageHeader = soapMessage.getHeader();
        if (messageHeader != null) {
            checkUnderstoodSOAPHeaders(soapMessage.getHeader().getUnknownXMLObjects());
        }

        List<XMLObject> soapBodyChildren = soapMessage.getBody().getUnknownXMLObjects();
        if (soapBodyChildren.size() < 1 || soapBodyChildren.size() > 1) {
            log.error("Unexpected number of children in the SOAP body, " + soapBodyChildren.size()
                    + ".  Unable to extract SAML message");
            throw new MessageDecodingException(
                    "Unexpected number of children in the SOAP body, unable to extract SAML message");
        }

        XMLObject incommingMessage = soapBodyChildren.get(0);
        if (!(incommingMessage instanceof SAMLObject)) {
            log.error("Unexpected SOAP body content.  Expected a SAML request but recieved {}", incommingMessage
                    .getElementQName());
            throw new MessageDecodingException("Unexpected SOAP body content.  Expected a SAML request but recieved "
                    + incommingMessage.getElementQName());
        }

        SAMLObject samlMessage = (SAMLObject) incommingMessage;
        log.debug("Decoded SOAP messaged which included SAML message of type {}", samlMessage.getElementQName());
        samlMsgCtx.setInboundSAMLMessage(samlMessage);

        populateMessageContext(samlMsgCtx);
    }

    /**
     * Checks that, if any SOAP headers, require understand that they are in the understood header list.
     *
     * @param headers SOAP headers to check
     *
     * @throws MessageDecodingException thrown if a SOAP header requires understanding but is not understood by the
     *             decoder
     */
    protected void checkUnderstoodSOAPHeaders(List<XMLObject> headers) throws MessageDecodingException {
        if (headers == null || headers.isEmpty()) {
            return;
        }

        AttributeExtensibleXMLObject attribExtensObject;
        for (XMLObject header : headers) {
            if (header instanceof AttributeExtensibleXMLObject) {
                attribExtensObject = (AttributeExtensibleXMLObject) header;
                if (DataTypeHelper.safeEquals("1", attribExtensObject.getUnknownAttributes().get(soapMustUnderstand))) {
                    if (!understoodHeaders.contains(header.getElementQName())) {
                        throw new MessageDecodingException("SOAP decoder encountered a header, "
                                + header.getElementQName()
                                + ", that requires understanding however this decoder does not understand that header");
                    }
                }
            }
        }
    }
}