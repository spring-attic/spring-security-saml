/*
 * Copyright 2011 Jonathan Tellier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.liberty.paos.impl;

import org.opensaml.common.impl.AbstractSAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.liberty.paos.Response;

public class ResponseBuilder extends AbstractSAMLObjectBuilder<Response> {
    
    /**
     * Constructor.
     */
    public ResponseBuilder() {

    }

    /** {@inheritDoc} */
    @Override
    public Response buildObject() {
        return buildObject(SAMLConstants.PAOS_NS, Response.DEFAULT_ELEMENT_LOCAL_NAME,
                SAMLConstants.PAOS_PREFIX);
    }

    /** {@inheritDoc} */
    @Override
    public Response buildObject(String namespaceURI, String localName,
            String namespacePrefix) {
        return new ResponseImpl(namespaceURI, localName, namespacePrefix);
    }

}
