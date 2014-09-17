/*
 * Copyright 2010 Vladimir Schaefer
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

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpClientInTransport;
import org.opensaml.ws.transport.http.LocationAwareInTransport;
import org.opensaml.xml.parse.ParserPool;

/**
 * Custom implementation of the decoder which takes into account user HTTPInput method
 * for determining correct expected URI.
 */
public class HTTPSOAP11DecoderImpl extends HTTPSOAP11Decoder {

    public HTTPSOAP11DecoderImpl(ParserPool pool) {
        super(pool);
    }   

    @Override
    protected String getActualReceiverEndpointURI(SAMLMessageContext messageContext) throws MessageDecodingException {

        InTransport inTransport = messageContext.getInboundMessageTransport();
        if (inTransport instanceof LocationAwareInTransport) {
            return ((LocationAwareInTransport)inTransport).getLocalAddress();
        } else {
            return super.getActualReceiverEndpointURI(messageContext);
        }

    }

    /**
     * In case message destination is set (was included in the message) check is made against the endpoint. Otherwise
     * always passes.
     *
     * @param messageDestination destination from the SAML message
     * @param receiverEndpoint   endpoint address
     * @return true if the endpoints are equivalent, false otherwise
     */
    @Override
    protected boolean compareEndpointURIs(String messageDestination, String receiverEndpoint) throws MessageDecodingException {

        // Message destination is not obligatory
        return messageDestination == null || super.compareEndpointURIs(messageDestination, receiverEndpoint);

    }

}