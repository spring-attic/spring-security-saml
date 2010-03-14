/*
 * Copyright 2009 Vladimir Schafer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.parser;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.impl.ActionImpl;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.springframework.security.saml.SAMLTestBase;
import org.w3c.dom.Element;

import java.io.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static org.easymock.EasyMock.*;

/**
 * @author Vladimir Schafer
 */
public class SAMLCollectionTest extends SAMLTestBase {

    SAMLCollection<Attribute> attributesObject;
    List<Attribute> attributes;

    @Before
    public void initializeValues() {

        Attribute attribute1 = ((SAMLObjectBuilder<Attribute>) SAMLTestBase.builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME)).buildObject();
        attribute1.setName("name1");
        Attribute attribute2 = ((SAMLObjectBuilder<Attribute>) SAMLTestBase.builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME)).buildObject();
        attribute2.setName("name2");

        attributes = new LinkedList<Attribute>(Arrays.asList(attribute1, attribute2));
        attributesObject = new SAMLCollection<Attribute>(attributes);

    }

    /**
     * Verfies that the inner object is set correctly.
     */
    @Test
    public void testGetInnerObject() {
        assertEquals(attributes, attributesObject.getObject());
    }

    /**
     * Verfies that SAMLObject can't be creaed with null argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNoNullArgument() {
        new SAMLCollection(null);
    }

    /**
     * Verifies that the SAMLCollection can be serialized/deserialized correctly.
     *
     * @throws Exception error
     */
    @Test
    public void testSerialization() throws Exception {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(attributesObject);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);
        SAMLCollection<Attribute> desAssertion = (SAMLCollection<Attribute>) input.readObject();

        assertEquals(2, desAssertion.getObject().size());
        assertEquals("name1", desAssertion.getObject().get(0).getName());
        assertEquals("name2", desAssertion.getObject().get(1).getName());
        assertEquals(attributesObject, desAssertion);

        // And for the second time, as we cache some data
        outStream = new ByteArrayOutputStream();
        stream = new ObjectOutputStream(outStream);
        stream.writeObject(attributesObject);

        inputStream = new ByteArrayInputStream(outStream.toByteArray());
        input = new ObjectInputStream(inputStream);
        desAssertion = (SAMLCollection<Attribute>) input.readObject();

        assertEquals(2, desAssertion.getObject().size());
        assertEquals("name1", desAssertion.getObject().get(0).getName());
        assertEquals("name2", desAssertion.getObject().get(1).getName());
        assertEquals(attributesObject, desAssertion);

        // And serialization of the already serialized data
        outStream = new ByteArrayOutputStream();
        stream = new ObjectOutputStream(outStream);
        stream.writeObject(desAssertion);

        inputStream = new ByteArrayInputStream(outStream.toByteArray());
        input = new ObjectInputStream(inputStream);
        SAMLCollection<Attribute> desAssertion2 = (SAMLCollection<Attribute>) input.readObject();

        assertEquals(2, desAssertion2.getObject().size());
        assertEquals("name1", desAssertion2.getObject().get(0).getName());
        assertEquals("name2", desAssertion2.getObject().get(1).getName());
        assertEquals(desAssertion, desAssertion2);

    }

}