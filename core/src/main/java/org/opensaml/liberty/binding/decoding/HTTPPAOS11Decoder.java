/*
 * Copyright 2010 Jonathan Tellier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.liberty.binding.decoding;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.saml2.ecp.impl.RelayStateImpl;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;

public class HTTPPAOS11Decoder extends HTTPSOAP11Decoder {

    public HTTPPAOS11Decoder() {
        super();
        initUnderstoodHeaders();
    }

    public HTTPPAOS11Decoder(ParserPool pool) {
        super(pool);
        initUnderstoodHeaders();
    }

    private void initUnderstoodHeaders() {
        QName paosResponse = new QName(SAMLConstants.PAOS_NS,
                "Response", SAMLConstants.PAOS_PREFIX);
        
        List<QName> headerNames = new ArrayList<QName>();
        headerNames.add(paosResponse);
        
        setUnderstoodHeaders(headerNames);
    }

    @Override
    protected void doDecode(MessageContext messageContext)
            throws MessageDecodingException {
        super.doDecode(messageContext);
        
        // Setting the RelayState in the message context
        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;
        Envelope soapMessage = (Envelope) samlMsgCtx.getInboundMessage();
        
        List<XMLObject> relayStateHeader = soapMessage.getHeader().getUnknownXMLObjects(
                new QName(SAMLConstants.SAML20ECP_NS,
                        RelayState.DEFAULT_ELEMENT_LOCAL_NAME,
                        SAMLConstants.SAML20ECP_PREFIX));
        
        if (relayStateHeader.size() == 1
            && relayStateHeader.get(0) instanceof RelayStateImpl) {
            samlMsgCtx.setRelayState(((RelayStateImpl) relayStateHeader.get(0)).getValue());
        }
    }

}
