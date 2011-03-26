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

import org.opensaml.common.BaseSAMLObjectProviderTestCase;
import org.opensaml.liberty.paos.Request;

/**
 * Test case for creating, marshalling, and unmarshalling {@link Request}.
 */
public class RequestTest extends BaseSAMLObjectProviderTestCase {
    
    private String expectedResponseConsumerURL;
    private String expectedService;
    private String expectedSOAP11Actor;
    private Boolean expectedSOAP11MustUnderstand;
    private String expectedMessageID;
    
    public RequestTest() {
        singleElementFile = "/org/opensaml/liberty/paos/impl/Request.xml";
        singleElementOptionalAttributesFile =
            "/org/opensaml/liberty/paos/impl/RequestOptionalAttributes.xml";
    }
    
    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        
        expectedResponseConsumerURL = "https://identity-service/SAML2/ECP";
        expectedService = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
        expectedSOAP11Actor = "http://schemas.xmlsoap.org/soap/actor/next";
        expectedSOAP11MustUnderstand = true;
        expectedMessageID = "6c3a4f8b9c2d";
    }

    /** {@inheritDoc} */
    @Override
    public void testSingleElementMarshall() {
        Request request = getRequestWithRequiredAttributes();
        
        assertEquals(expectedDOM, request);
    }
    
    /** {@inheritDoc} */
    @Override
    public void testSingleElementOptionalAttributesMarshall() {
        Request request = getRequestWithRequiredAttributes();
        
        request.setMessageID(expectedMessageID);
        
        assertEquals(expectedOptionalAttributesDOM, request);        
    }
    
    private Request getRequestWithRequiredAttributes() {
        Request request = (Request) buildXMLObject(Request.DEFAULT_ELEMENT_NAME);
        
        request.setResponseConsumerURL(expectedResponseConsumerURL);
        request.setService(expectedService);
        request.setSOAP11Actor(expectedSOAP11Actor);
        request.setSOAP11MustUnderstand(expectedSOAP11MustUnderstand);
        return request;
    }

    /** {@inheritDoc} */
    @Override
    public void testSingleElementUnmarshall() {
        Request request = (Request) unmarshallElement(singleElementFile);
        
        testRequestRequiredElements(request);
    }
    
    /** {@inheritDoc} */
    @Override
    public void testSingleElementOptionalAttributesUnmarshall() {
        Request request = (Request) unmarshallElement(singleElementOptionalAttributesFile);
        
        testRequestRequiredElements(request);
        
        assertEquals("messageID had unexpected value", expectedMessageID,
                request.getMessageID());
    }

    private void testRequestRequiredElements(Request request) {
        assertNotNull(request);
        
        assertEquals("responseConsumerURL had unexpected value",
                expectedResponseConsumerURL, request.getResponseConsumerURL());
        assertEquals("service had unexpected value",
                expectedService, request.getService());
        assertEquals("SOAP mustUnderstand had unexpected value",
                expectedSOAP11MustUnderstand, request.isSOAP11MustUnderstand());
        assertEquals("SOAP actor had unexpected value",
                expectedSOAP11Actor, request.getSOAP11Actor());
    }
    

}
