/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

package org.opensaml.common;

import javax.xml.namespace.QName;

import org.custommonkey.xmlunit.XMLTestCase;
import org.custommonkey.xmlunit.XMLUnit;
import org.opensaml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Intermediate class that serves to initialize the configuration environment for other base test classes.
 */
public abstract class BaseTestCase extends XMLTestCase {
    
    /** Parser manager used to parse XML. */
    protected static BasicParserPool parser;
    
    /** XMLObject builder factory. */
    protected static XMLObjectBuilderFactory builderFactory;

    /** XMLObject marshaller factory. */
    protected static MarshallerFactory marshallerFactory;

    /** XMLObject unmarshaller factory. */
    protected static UnmarshallerFactory unmarshallerFactory;
    
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(BaseTestCase.class);
    
    /** Constructor. */
    public BaseTestCase(){
        super();
        
        parser = new BasicParserPool();
        parser.setNamespaceAware(true);
        builderFactory = Configuration.getBuilderFactory();
        marshallerFactory = Configuration.getMarshallerFactory();
        unmarshallerFactory = Configuration.getUnmarshallerFactory();
    }

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        XMLUnit.setIgnoreWhitespace(true);
        
        try{
            BootstrapHelper.bootstrap();
        }catch(ConfigurationException e){
            fail(e.getMessage());
        }
    }

    /** {@inheritDoc} */
    protected void tearDown() throws Exception {
        super.tearDown();
    }
    /**
     * Asserts a given XMLObject is equal to an expected DOM. The XMLObject is marshalled and the resulting DOM object
     * is compared against the expected DOM object for equality.
     * 
     * @param expectedDOM the expected DOM
     * @param xmlObject the XMLObject to be marshalled and compared against the expected DOM
     */
    public void assertEquals(Document expectedDOM, XMLObject xmlObject) {
        assertEquals("Marshalled DOM was not the same as the expected DOM", expectedDOM, xmlObject);
    }

    /**
     * Asserts a given XMLObject is equal to an expected DOM. The XMLObject is marshalled and the resulting DOM object
     * is compared against the expected DOM object for equality.
     * 
     * @param failMessage the message to display if the DOMs are not equal
     * @param expectedDOM the expected DOM
     * @param xmlObject the XMLObject to be marshalled and compared against the expected DOM
     */
    public void assertEquals(String failMessage, Document expectedDOM, XMLObject xmlObject) {
        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        if(marshaller == null){
            fail("Unable to locate marshaller for " + xmlObject.getElementQName() + " can not perform equality check assertion");
        }
        
        try {
            Element generatedDOM = marshaller.marshall(xmlObject, parser.newDocument());
            if(log.isDebugEnabled()) {
                log.debug("Marshalled DOM was " + XMLHelper.nodeToString(generatedDOM));
            }
            assertXMLEqual(failMessage, expectedDOM, generatedDOM.getOwnerDocument());
        } catch (Exception e) {
            log.error("Marshalling failed with the following error:", e);
            fail("Marshalling failed with the following error: " + e);
        }
    }
    
    /**
     * Builds the requested XMLObject.
     * 
     * @param objectQName name of the XMLObject
     * 
     * @return the build XMLObject
     */
    public XMLObject buildXMLObject(QName objectQName){
        XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objectQName);
        if(builder == null){
            fail("Unable to retrieve builder for object QName " + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }
    
    /**
     * Unmarshalls an element file into its SAMLObject.
     * 
     * @param elementFile the classpath path to an XML document to unmarshall
     * 
     * @return the SAMLObject from the file
     */
    protected XMLObject unmarshallElement(String elementFile) {
        try {
            Document doc = parser.parse(BaseTestCase.class
                    .getResourceAsStream(elementFile));
            Element samlElement = doc.getDocumentElement();

            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
            if (unmarshaller == null) {
                fail("Unable to retrieve unmarshaller by DOM Element");
            }

            return unmarshaller.unmarshall(samlElement);
        } catch (XMLParserException e) {
            fail("Unable to parse element file " + elementFile);
        } catch (UnmarshallingException e) {
            fail("Unmarshalling failed when parsing element file " + elementFile + ": " + e);
        }

        return null;
    }
}