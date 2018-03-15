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
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.handler.HandlerChain;
import org.opensaml.ws.message.handler.HandlerChainAware;
import org.opensaml.ws.message.handler.HandlerChainResolver;
import org.opensaml.ws.message.handler.HandlerException;
import org.opensaml.xml.parse.ParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML 2.0 SOAP 1.1 over HTTP binding decoder with support for handler chains.
 */
public class HandlerChainAwareHTTPSOAP11Decoder extends HTTPSOAP11Decoder implements HandlerChainAware {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HandlerChainAwareHTTPSOAP11Decoder.class);

    /** Constructor.  */
    public HandlerChainAwareHTTPSOAP11Decoder() {
        super();
    }

    /**
     * Constructor.
     *
     * @param pool parser pool to use
     */
    public HandlerChainAwareHTTPSOAP11Decoder(ParserPool pool) {
        super(pool);
    }

    // TODO: The rest of the methods here are copied from BaseHandlerChainAwareMessageDecoder and
    // should drop out once the SAML decoders are aligned to that base class.

    /** {@inheritDoc} */
    public void decode(MessageContext messageContext) throws MessageDecodingException, SecurityException {
        log.debug("Beginning to decode message from inbound transport of type: {}", messageContext
                .getInboundMessageTransport().getClass().getName());

        doDecode(messageContext);

        logDecodedMessage(messageContext);

        processPreSecurityInboundHandlerChain(messageContext);
        log.debug("Successfully processed pre-SecurityPolicy inbound handler chain.");

        processSecurityPolicy(messageContext);

        processPostSecurityInboundHandlerChain(messageContext);
        log.debug("Successfully processed post-SecurityPolicy inbound handler chain.");

        log.debug("Successfully decoded message.");

        // TODO: This gets executed by BaseSAML2MessageDecoder. Probably needs to be
        // factored out somehow to avoid brittleness in the decode() override.
        checkEndpointURI((SAMLMessageContext) messageContext);
    }

    /**
     * Process the pre-SecurityPolicy inbound {@link HandlerChain} for the message context, if any.
     *
     * @param messageContext the message context to process
     * @throws MessageDecodingException thrown if a handler indicates a problem handling the message
     */
    protected void processPreSecurityInboundHandlerChain(MessageContext messageContext)
            throws MessageDecodingException {
        HandlerChainResolver inboundHandlerChainResolver = messageContext.getPreSecurityInboundHandlerChainResolver();
        if (inboundHandlerChainResolver != null) {
            log.debug("Invoking pre-SecurityPolicy inbound handler chain on message context");
            try {
                for (HandlerChain inboundHandlerChain : inboundHandlerChainResolver.resolve(messageContext)) {
                    if (inboundHandlerChain != null) {
                        invokeHandlerChain(inboundHandlerChain, messageContext);
                    }
                }
            } catch (HandlerException e) {
                log.error("Encountered pre-SecurityPolicy HandlerException when decoding message: {}", e.getMessage());
                throw new MessageDecodingException("Pre-SecurityPolicy Handler exception while decoding message", e);
            }
        }
    }

    /**
     * Process the post-SecurityPolicy inbound {@link HandlerChain} for the message context, if any.
     *
     * @param messageContext the message context to process
     * @throws MessageDecodingException thrown if a handler indicates a problem handling the message
     */
    protected void processPostSecurityInboundHandlerChain(MessageContext messageContext)
            throws MessageDecodingException {
        HandlerChainResolver inboundHandlerChainResolver = messageContext.getPostSecurityInboundHandlerChainResolver();
        if (inboundHandlerChainResolver != null) {
            log.debug("Invoking post-SecurityPolicy inbound handler chain on message context");
            try {
                for (HandlerChain inboundHandlerChain : inboundHandlerChainResolver.resolve(messageContext)) {
                    if (inboundHandlerChain != null) {
                        invokeHandlerChain(inboundHandlerChain, messageContext);
                    }
                }
            } catch (HandlerException e) {
                log.error("Encountered post-SecurityPolicy HandlerException when decoding message: {}", e.getMessage());
                throw new MessageDecodingException("Handler exception while decoding message", e);
            }
        }
    }

    /**
     * Invoke a handler chain on the specified message context.
     *
     * @param handlerChain the handle chain to invoke
     * @param messageContext the message context to process
     *
     * @throws HandlerException if handler chain encountered a problem handling the message context
     */
    protected void invokeHandlerChain(HandlerChain handlerChain, MessageContext messageContext)
            throws HandlerException {
        if (handlerChain != null && messageContext != null) {
            handlerChain.invoke(messageContext);
        }
    }

}
