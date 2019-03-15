/*
 * Copyright 2011 Jonathan Tellier
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

import java.util.List;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.liberty.paos.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSBooleanValue;

public class ResponseImpl extends AbstractSAMLObject implements Response {
    
    /** refToMessageID attribute */
    private String refToMessageID;
    
    /** soap11:actor attribute. */
    private String soap11Actor;
    
    /** soap11:mustUnderstand. */
    private XSBooleanValue soap11MustUnderstand;

    /**
     * Constructor.
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected ResponseImpl(String namespaceURI, String elementLocalName,
            String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /** {@inheritDoc} */
    public String getRefToMessageID() {
        return refToMessageID;
    }

    /** {@inheritDoc} */
    public void setRefToMessageID(String newRefToMessageID) {
        refToMessageID = prepareForAssignment(refToMessageID, newRefToMessageID);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getOrderedChildren() {
     // No elements
        return null;
    }

    /** {@inheritDoc} */
    public Boolean isSOAP11MustUnderstand() {
        if (soap11MustUnderstand != null) {
            return soap11MustUnderstand.getValue();
        }
        return Boolean.FALSE;
    }

    /** {@inheritDoc} */
    public XSBooleanValue isSOAP11MustUnderstandXSBoolean() {
        return soap11MustUnderstand;
    }

    /** {@inheritDoc} */
    public void setSOAP11MustUnderstand(Boolean newMustUnderstand) {
        if (newMustUnderstand != null) {
            soap11MustUnderstand = prepareForAssignment(soap11MustUnderstand, 
                    new XSBooleanValue(newMustUnderstand, true));
        } else {
            soap11MustUnderstand = prepareForAssignment(soap11MustUnderstand, null);
        }
    }

    /** {@inheritDoc} */
    public void setSOAP11MustUnderstand(XSBooleanValue newMustUnderstand) {
            soap11MustUnderstand = prepareForAssignment(soap11MustUnderstand,
                    newMustUnderstand);
    }

    /** {@inheritDoc} */
    public String getSOAP11Actor() {
        return soap11Actor;
    }

    /** {@inheritDoc} */
    public void setSOAP11Actor(String newActor) {
        soap11Actor = prepareForAssignment(soap11Actor, newActor);
    }

}
