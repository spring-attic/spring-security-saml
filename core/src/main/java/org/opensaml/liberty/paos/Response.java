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

package org.opensaml.liberty.paos;

import javax.xml.namespace.QName;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.soap.soap11.ActorBearing;
import org.opensaml.ws.soap.soap11.MustUnderstandBearing;

/**
 * Liberty Alliance PAOS Response header.
 */
public interface Response extends SAMLObject, MustUnderstandBearing,
        ActorBearing {
    
    /** Element local name. */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "Response";

    /** Default element name. */
    public static final QName DEFAULT_ELEMENT_NAME =
        new QName(SAMLConstants.PAOS_NS, DEFAULT_ELEMENT_LOCAL_NAME,
                SAMLConstants.PAOS_PREFIX);

    /** Local name of the XSI type. */
    public static final String TYPE_LOCAL_NAME = "ResponseType";

    /** QName of the XSI type. */
    public static final QName TYPE_NAME =
        new QName(SAMLConstants.PAOS_NS, TYPE_LOCAL_NAME, SAMLConstants.PAOS_PREFIX);

    /** messageID attribute name. */
    public static final String REF_TO_MESSAGE_ID_ATTRIB_NAME = "refToMessageID";
    
    /**
     * Get the refToMessageID attribute value.
     * 
     * @return the refToMessageID attribute value
     */
    public String getRefToMessageID();
    
    /**
     * Set the refToMessageID attribute value.
     * 
     * @param newRefToMessageID the new refToMessageID attribute value
     */
    public void setRefToMessageID(String newRefToMessageID);

}
