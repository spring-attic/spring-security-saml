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

package org.opensaml.liberty.paos.impl;

import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.liberty.paos.Request;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 * Marshaller for instances of {@link Request}.
 */
public class RequestMarshaller extends AbstractSAMLObjectMarshaller {
    
    /** {@inheritDoc} */
    protected void marshallAttributes(XMLObject xmlObject, Element domElement)
            throws MarshallingException {
        Request request = (Request) xmlObject;
        
        if (request.getResponseConsumerURL() != null) {
            domElement.setAttributeNS(null, Request.RESPONSE_CONSUMER_URL_ATTRIB_NAME,
                    request.getResponseConsumerURL());
        }
        if (request.getService() != null) {
            domElement.setAttributeNS(null, Request.SERVICE_ATTRIB_NAME, request.getService());
        }
        if (request.getMessageID() != null) {
            domElement.setAttributeNS(null, Request.MESSAGE_ID_ATTRIB_NAME,
                    request.getMessageID());
        }
        if (request.isSOAP11MustUnderstandXSBoolean() != null) {
            XMLHelper.marshallAttribute(Request.SOAP11_MUST_UNDERSTAND_ATTR_NAME, 
                    request.isSOAP11MustUnderstandXSBoolean().toString(), domElement, false);
        }
        if (request.getSOAP11Actor() != null) {
            XMLHelper.marshallAttribute(Request.SOAP11_ACTOR_ATTR_NAME, 
                    request.getSOAP11Actor(), domElement, false);
        }
        
    }
}
