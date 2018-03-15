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

import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.transport.InTransport;
import org.opensaml.compat.transport.http.HttpServletRequestAdapter;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Base class for all SAML message decoders.
 */
public abstract class BaseSAMLMessageDecoder extends BaseMessageDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(BaseSAMLMessageDecoder.class);

    /** The URIComparator implementation to use. */
    private URIComparator uriComparator;

    /** Constructor. */
    public BaseSAMLMessageDecoder() {
        super();
        setURIComparator(new BasicURLComparator());
    }

    /**
     * Constructor.
     *
     * @param pool parser pool used to deserialize messages
     */
    public BaseSAMLMessageDecoder(ParserPool pool) {
        super(pool);
        setURIComparator(new BasicURLComparator());
    }

    /**
     * Set the {@link URIComparator} to use in {@link #compareEndpointURIs(String, String)}.
     *
     * @param comparator The uriComparator to set.
     */
    public void setURIComparator(URIComparator comparator) {
        if (comparator == null) {
            throw new IllegalArgumentException("URI comparator may not be null");
        }
        uriComparator = comparator;
    }

    /**
     * Get the {@link URIComparator} to use in {@link #compareEndpointURIs(String, String)}.
     *
     * @return Returns the uriComparator.
     */
    public URIComparator getURIComparator() {
        return uriComparator;
    }

    /**
     * Determine whether the SAML message represented by the message context is digitally signed.
     *
     * <p>The default behavior is to examine whether an XML signature is present on the
     * SAML protocol message.  Subclasses may augment or replace with binding-specific behavior.</p>
     *
     * @param messageContext current message context
     * @return true if the message is considered to be digitially signed, false otherwise
     */
    protected boolean isMessageSigned(SAMLMessageContext messageContext) {
        SAMLObject samlMessage = messageContext.getInboundSAMLMessage();
        if (samlMessage instanceof SignableSAMLObject) {
            return ((SignableSAMLObject)samlMessage).isSigned();
        } else {
            return false;
        }
    }

    /**
     * Determine whether the binding implemented by the decoder requires the presence within the message
     * of information indicating the intended message destination endpoint URI.
     *
     *
     * @param samlMsgCtx current SAML message context
     * @return true if the intended message destination endpoint is required, false if not
     */
    protected abstract boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx);

    /**
     * Extract the message information which indicates to what receiver endpoint URI the
     * SAML message was intended to be delivered.
     *
     * @param samlMsgCtx the SAML message context being processed
     * @return the value of the intended destination endpoint URI, or null if not present or empty
     * @throws MessageDecodingException thrown if the message is not an instance of SAML message that
     *              could be processed by the decoder
     */
    protected abstract String getIntendedDestinationEndpointURI(SAMLMessageContext samlMsgCtx)
        throws MessageDecodingException;

    /**
     * Extract the transport endpoint at which this message was received.
     *
     * <p>This default implementation assumes an underlying message context {@link InTransport} type
     * of {@link HttpServletRequestAdapter} and returns the string representation of the underlying
     * request URL as constructed via {@link HttpServletRequest#getRequestURL()}.</p>
     *
     * <p>Subclasses should override if binding-specific behavior or support for other transport
     * typs is required.  In this case, see also {@link #compareEndpointURIs(String, String)}.</p>
     *
     *
     * @param messageContext current message context
     * @return string representing the transport endpoint URI at which the current message was received
     * @throws MessageDecodingException thrown if the endpoint can not be extracted from the message
     *                              context and converted to a string representation
     */
    protected String getActualReceiverEndpointURI(SAMLMessageContext messageContext) throws MessageDecodingException {
        InTransport inTransport = messageContext.getInboundMessageTransport();
        if (! (inTransport instanceof HttpServletRequestAdapter)) {
            log.error("Message context InTransport instance was an unsupported type: {}",
                    inTransport.getClass().getName());
            throw new MessageDecodingException("Message context InTransport instance was an unsupported type");
        }
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter)inTransport).getWrappedRequest();

        StringBuffer urlBuilder = httpRequest.getRequestURL();

        return urlBuilder.toString();
    }

    /**
     * Compare the message endpoint URI's specified.
     *
     * <p>The comparison is performed using the configured instance of {@link URIComparator}.
     * By default, the URL subtype of URI is supported, and the default comparator implementation used
     * is {@link BasicURLComparator}. Other types of URI's may be supported by configuring a
     * different implementation of {@link URIComparator}.
     * </p>
     *
     * <p>Subclasses should override if binding-specific behavior is required.
     * In this case, see also {@link #getActualReceiverEndpointURI(SAMLMessageContext)}.</p>
     *
     * @param messageDestination the intended message destination endpoint URI
     * @param receiverEndpoint the endpoint URI at which the message was received
     * @return true if the endpoints are equivalent, false otherwise
     * @throws MessageDecodingException thrown if the endpoints specified are not equivalent
     */
    protected boolean compareEndpointURIs(String messageDestination, String receiverEndpoint)
            throws MessageDecodingException {

        return getURIComparator().compare(messageDestination, receiverEndpoint);
    }

    /**
     * Check the validity of the SAML protocol message receiver endpoint against
     * requirements indicated in the message.
     *
     * @param messageContext current message context
     *
     * @throws SecurityException thrown if the message Destination attribute is invalid
     *                                  with respect to the receiver's endpoint
     * @throws MessageDecodingException thrown if there is a problem decoding and processing
     *                                  the message Destination or receiver
     *                                  endpoint information
     */
    protected void checkEndpointURI(SAMLMessageContext messageContext)
            throws SecurityException, MessageDecodingException {

        log.debug("Checking SAML message intended destination endpoint against receiver endpoint");

        String messageDestination =
            DataTypeHelper.safeTrimOrNullString(getIntendedDestinationEndpointURI(messageContext));

        boolean bindingRequires = isIntendedDestinationEndpointURIRequired(messageContext);

        if (messageDestination == null) {
            if (bindingRequires) {
                log.error("SAML message intended destination endpoint URI required by binding was empty");
                throw new SecurityException("SAML message intended destination (required by binding) was not present");
            } else {
                log.debug("SAML message intended destination endpoint in message was empty, not required by binding, skipping");
                return;
            }
        }

        String receiverEndpoint = DataTypeHelper.safeTrimOrNullString(getActualReceiverEndpointURI(messageContext));

        log.debug("Intended message destination endpoint: {}", messageDestination);
        log.debug("Actual message receiver endpoint: {}", receiverEndpoint);

        boolean matched = compareEndpointURIs(messageDestination, receiverEndpoint);
        if (!matched) {
            log.error("SAML message intended destination endpoint '{}' did not match the recipient endpoint '{}'",
                    messageDestination, receiverEndpoint);
            throw new SecurityException("SAML message intended destination endpoint did not match recipient endpoint");
        } else {
            log.debug("SAML message intended destination endpoint matched recipient endpoint");
        }
    }

}
