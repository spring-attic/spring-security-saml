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

package org.opensaml.liberty.paos;

import javax.xml.namespace.QName;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.soap.soap11.ActorBearing;
import org.opensaml.ws.soap.soap11.MustUnderstandBearing;

/**
 * Liberty Alliance PAOS Request header.
 */
public interface Request extends SAMLObject, MustUnderstandBearing,
        ActorBearing {
    
    /** Element local name. */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "Request";

    /** Default element name. */
    public static final QName DEFAULT_ELEMENT_NAME =
        new QName(SAMLConstants.PAOS_NS, DEFAULT_ELEMENT_LOCAL_NAME,
                SAMLConstants.PAOS_PREFIX);

    /** Local name of the XSI type. */
    public static final String TYPE_LOCAL_NAME = "RequestType";

    /** QName of the XSI type. */
    public static final QName TYPE_NAME =
        new QName(SAMLConstants.PAOS_NS, TYPE_LOCAL_NAME, SAMLConstants.PAOS_PREFIX);

    /** responseConsumerURL attribute name. */
    public static final String RESPONSE_CONSUMER_URL_ATTRIB_NAME = "responseConsumerURL";

    /** service attribute name. */
    public static final String SERVICE_ATTRIB_NAME = "service";
    
    /** messageID attribute name. */
    public static final String MESSAGE_ID_ATTRIB_NAME = "messageID";
    
    /**
     * Get the responseConsumerURL attribute value.
     * 
     * @return the responseConsumerURL attribute value
     */
    public String getResponseConsumerURL();
    
    /**
     * Set the responseConsumerURL attribute value.
     * 
     * @param newResponseConsumerURL the new responseConsumerURL attribute value
     */
    public void setResponseConsumerURL(String newResponseConsumerURL);
    
    /**
     * Get the service attribute value.
     * 
     * @return the service attribute value
     */
    public String getService();
    
    /**
     * Set the service attribute value.
     * 
     * @param newService the new service attribute value
     */
    public void setService(String newService);
    
    /**
     * Get the messageID attribute value.
     * 
     * @return the messageID attribute value
     */
    public String getMessageID();
    
    /**
     * Set the messageID attribute value.
     * 
     * @param newMessageID the new messageID attribute value
     */
    public void setMessageID(String newMessageID);

}
