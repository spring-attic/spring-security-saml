/*
 * Copyright 2010 Jonathan Tellier
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

import javax.xml.namespace.QName;

import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.liberty.paos.Request;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Attr;

/**
 * Unmarshaller for instances of {@link Request}.
 */
public class RequestUnmarshaller extends AbstractSAMLObjectUnmarshaller {
    
    /** {@inheritDoc} */
    protected void processAttribute(XMLObject samlObject, Attr attribute)
            throws UnmarshallingException {
        Request request = (Request) samlObject;
        
        QName attrName = XMLHelper.getNodeQName(attribute);
        if (Request.SOAP11_MUST_UNDERSTAND_ATTR_NAME.equals(attrName)) {
            request.setSOAP11MustUnderstand(XSBooleanValue.valueOf(attribute.getValue()));
        } else if (Request.SOAP11_ACTOR_ATTR_NAME.equals(attrName)) {
            request.setSOAP11Actor(attribute.getValue()); 
        } else if (Request.RESPONSE_CONSUMER_URL_ATTRIB_NAME.equals(attribute.getLocalName())) {
            request.setResponseConsumerURL(attribute.getValue());
        } else if (Request.SERVICE_ATTRIB_NAME.equals(attribute.getLocalName())) {
            request.setService(attribute.getValue());
        } else if (Request.MESSAGE_ID_ATTRIB_NAME.equals(attribute.getLocalName())) {
            request.setMessageID(attribute.getValue());
        } else {
            super.processAttribute(samlObject, attribute);
        }
        
    }

}
