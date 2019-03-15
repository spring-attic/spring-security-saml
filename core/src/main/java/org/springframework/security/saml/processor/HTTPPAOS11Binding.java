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
package org.springframework.security.saml.processor;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.liberty.binding.decoding.HTTPPAOS11Decoder;
import org.opensaml.liberty.binding.encoding.HTTPPAOS11Encoder;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.parse.ParserPool;

import javax.servlet.http.HttpServletRequest;

public class HTTPPAOS11Binding extends HTTPSOAP11Binding {

	public HTTPPAOS11Binding(ParserPool parserPool) {
		super(new HTTPPAOS11Decoder(parserPool), new HTTPPAOS11Encoder());
	}

    public HTTPPAOS11Binding(MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
    }

    @Override
    public boolean supports(InTransport transport) {
	    if (transport instanceof HttpServletRequestAdapter) {
	        HttpServletRequestAdapter t = (HttpServletRequestAdapter) transport;
			if(!"POST".equalsIgnoreCase(t.getHTTPMethod())){
				return false;
			}
	        HttpServletRequest request = t.getWrappedRequest();
			String contentType = request.getContentType();
			return contentType != null
					&& contentType.startsWith(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_ACCEPT_HEADER);
	    } else {
	        return false;
	    }
    }

    @Override
	public String getBindingURI() {
		return SAMLConstants.SAML2_PAOS_BINDING_URI;
	}

}
