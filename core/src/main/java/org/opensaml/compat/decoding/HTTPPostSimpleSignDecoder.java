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

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.util.DataTypeHelper;

/** Message decoder implementing the SAML 2.0 HTTP POST-SimpleSign binding. */
public class HTTPPostSimpleSignDecoder extends HTTPPostDecoder {

    /**
     * Constructor.
     *
     */
    public HTTPPostSimpleSignDecoder() {
        super();
    }

    /**
     * Constructor.
     *
     * @param pool parser pool used to deserialize messages
     */
    public HTTPPostSimpleSignDecoder(ParserPool pool) {
        super();

    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_SIMPLE_SIGN_BINDING_URI;
    }

    /** {@inheritDoc} */
    protected boolean isMessageSigned(SAMLMessageContext messageContext) {
        HTTPInTransport inTransport = (HTTPInTransport) messageContext.getInboundMessageTransport();
        String sigParam = inTransport.getParameterValue("Signature");
        return (!DataTypeHelper.isEmpty(sigParam)) || super.isMessageSigned(messageContext);
    }

}
