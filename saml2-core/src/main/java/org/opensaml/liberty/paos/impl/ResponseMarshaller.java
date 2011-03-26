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

import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.liberty.paos.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 * Marshaller for instances of {@link Response}.
 */
public class ResponseMarshaller extends AbstractSAMLObjectMarshaller {
    
    /** {@inheritDoc} */
    protected void marshallAttributes(XMLObject xmlObject, Element domElement)
            throws MarshallingException {
        Response response = (Response) xmlObject;
        
        if (response.getRefToMessageID() != null) {
            domElement.setAttributeNS(null, Response.REF_TO_MESSAGE_ID_ATTRIB_NAME,
                    response.getRefToMessageID());
        }
        if (response.isSOAP11MustUnderstandXSBoolean() != null) {
            XMLHelper.marshallAttribute(Response.SOAP11_MUST_UNDERSTAND_ATTR_NAME, 
                    response.isSOAP11MustUnderstandXSBoolean().toString(), domElement, false);
        }
        if (response.getSOAP11Actor() != null) {
            XMLHelper.marshallAttribute(Response.SOAP11_ACTOR_ATTR_NAME, 
                    response.getSOAP11Actor(), domElement, false);
        }
        
    }
}
