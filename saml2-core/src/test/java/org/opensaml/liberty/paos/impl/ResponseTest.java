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

import org.opensaml.common.BaseSAMLObjectProviderTestCase;
import org.opensaml.liberty.paos.Response;

/**
 * Test case for creating, marshalling, and unmarshalling {@link Response}.
 */
public class ResponseTest extends BaseSAMLObjectProviderTestCase {
    
    private String expectedSOAP11Actor;
    private Boolean expectedSOAP11MustUnderstand;
    private String expectedRefToMessageID;
    
    public ResponseTest() {
        singleElementFile = "/org/opensaml/liberty/paos/impl/Response.xml";
        singleElementOptionalAttributesFile =
            "/org/opensaml/liberty/paos/impl/ResponseOptionalAttributes.xml";
    }
    
    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        
        expectedSOAP11Actor = "http://schemas.xmlsoap.org/soap/actor/next";
        expectedSOAP11MustUnderstand = true;
        expectedRefToMessageID = "6c3a4f8b9c2d";
    }

    /** {@inheritDoc} */
    @Override
    public void testSingleElementMarshall() {
        Response response = getResponseWithRequiredAttributes();
        
        assertEquals(expectedDOM, response);
    }
    
    /** {@inheritDoc} */
    @Override
    public void testSingleElementOptionalAttributesMarshall() {
        Response response = getResponseWithRequiredAttributes();
        
        response.setRefToMessageID(expectedRefToMessageID);
        
        assertEquals(expectedOptionalAttributesDOM, response);        
    }
    
    private Response getResponseWithRequiredAttributes() {
        Response response = (Response) buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
        
        response.setSOAP11Actor(expectedSOAP11Actor);
        response.setSOAP11MustUnderstand(expectedSOAP11MustUnderstand);
        return response;
    }

    /** {@inheritDoc} */
    @Override
    public void testSingleElementUnmarshall() {
        Response response = (Response) unmarshallElement(singleElementFile);
        
        testResponseRequiredElements(response);
    }
    
    /** {@inheritDoc} */
    @Override
    public void testSingleElementOptionalAttributesUnmarshall() {
        Response response = (Response) unmarshallElement(singleElementOptionalAttributesFile);
        
        testResponseRequiredElements(response);
        
        assertEquals("refToMessageID had unexpected value", expectedRefToMessageID,
                response.getRefToMessageID());
    }

    private void testResponseRequiredElements(Response response) {
        assertNotNull(response);
        
        assertEquals("SOAP mustUnderstand had unexpected value",
                expectedSOAP11MustUnderstand, response.isSOAP11MustUnderstand());
        assertEquals("SOAP actor had unexpected value",
                expectedSOAP11Actor, response.getSOAP11Actor());
    }
}
