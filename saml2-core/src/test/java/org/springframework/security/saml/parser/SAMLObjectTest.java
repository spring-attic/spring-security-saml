/* Copyright 2009 Vladimir Schaefer
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
import org.opensaml.saml2.core.impl.ActionImpl;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.saml.SAMLTestHelper;
import org.springframework.security.saml.util.SAMLUtil;
import org.w3c.dom.Element;

import java.io.*;

import static junit.framework.Assert.assertEquals;
import static org.easymock.EasyMock.*;

/**
 * @author Vladimir Schaefer
 */
public class SAMLObjectTest {

    SAMLObject<Assertion> assertionObject;
    Assertion assertion;

    @Before
    public void initializeValues() {
        assertion = ((SAMLObjectBuilder<Assertion>) SAMLTestHelper.getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME)).buildObject();
        assertion.setID("testID");

        assertionObject = new SAMLObject<Assertion>(assertion);
    }

    /**
     * Verifies that the inner object is set correctly.
     */
    @Test
    public void testGetInnerObject() {
        assertEquals(assertion, assertionObject.getObject());
    }

    /**
     * Verifies that SAMLObject can't be created with null argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNoNullArgument() {
        new SAMLObject(null);
    }

    /**
     * Verifies that deserializaion succeeds even without explicit parserPool initialization.
     *
     * @throws Exception error
     */
    @Test
    public void testMarshalWithoutPoolSet() throws Exception {

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(assertionObject);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);
        SAMLBase o = (SAMLBase) input.readObject();
        o.getObject();

    }

    /**
     * Verifies that deserializaion succeeds when parser pool is set when the object is accessed.
     *
     * @throws Exception error
     */
    @Test
    public void testMarshalWithLazyPoolSet() throws Exception {

        ParserPool pool = ParserPoolHolder.getPool();

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(assertionObject);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);
        SAMLBase o = (SAMLBase) input.readObject();


        o.getObject();

    }

    /**
     * Verifies that marshalling of object which doesn't have marshaller registered will fail.
     *
     * @throws Exception error
     */
    @Test(expected = MessageEncodingException.class)
    public void testMarshallObjectWithoutMarshaller() throws Exception {
        TestObject to = new TestObject("xxx", "", "");
        SAMLObject<TestObject> tso = new SAMLObject<TestObject>(to);

        Configuration.getMarshallerFactory().deregisterMarshaller(to.getElementQName());
        SAMLUtil.marshallMessage(to);
    }

    /**
     * Verifies that error during marshalling of object will be reported.
     *
     * @throws Exception error
     */
    @Test(expected = IOException.class)
    public void testMarshallingError() throws Exception {
        TestObject to = new TestObject("xxx", "", "");
        SAMLObject<TestObject> tso = new SAMLObject<TestObject>(to);

        Marshaller mock = createMock(Marshaller.class);
        Configuration.getMarshallerFactory().registerMarshaller(to.getElementQName(), mock);

        expect(mock.marshall(to)).andThrow(new MarshallingException("Error"));

        replay(mock);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(tso);
        verify(mock);
    }

    /**
     * Verifies that unmarshalling XML for which no unmarshaller is registered will fail with exception.
     *
     * @throws Exception error
     */
    @Test(expected = RuntimeException.class)
    public void testNoUnmarshaller() throws Exception {

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(assertionObject);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);

        Unmarshaller old = Configuration.getUnmarshallerFactory().getUnmarshaller(assertion.getElementQName());

        try {
            Configuration.getUnmarshallerFactory().deregisterUnmarshaller(assertion.getElementQName());
            SAMLBase o = (SAMLBase) input.readObject();
            o.getObject();
        } finally {
            Configuration.getUnmarshallerFactory().registerUnmarshaller(assertion.getElementQName(), old);
        }

    }

    class TestObject extends ActionImpl {
        TestObject(String namespaceURI, String elementLocalName, String namespacePrefix) {
            super(namespaceURI, elementLocalName, namespacePrefix);
        }
    }

    /**
     * Verifies that error during unmarshalling will be reported.
     *
     * @throws Exception error
     */
    @Test(expected = RuntimeException.class)
    public void testWrongXMLInStream() throws Exception {

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(assertionObject);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);

        Unmarshaller mock = createMock(Unmarshaller.class);
        Unmarshaller old = Configuration.getUnmarshallerFactory().getUnmarshaller(assertion.getElementQName());
        Configuration.getUnmarshallerFactory().registerUnmarshaller(assertion.getElementQName(), mock);

        expect(mock.unmarshall((Element) notNull())).andThrow(new UnmarshallingException(""));

        try {
            replay(mock);
            SAMLBase o = (SAMLBase) input.readObject();
            o.getObject();
            verify(mock);
        } finally {
            Configuration.getUnmarshallerFactory().registerUnmarshaller(assertion.getElementQName(), old);
        }
    }

    /**
     * Verifies that the SAMLCredential can be serialized/deserialized correctly.
     *
     * @throws Exception error
     */
    @Test
    public void testSerialization() throws Exception {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ObjectOutputStream stream = new ObjectOutputStream(outStream);
        stream.writeObject(assertionObject);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);
        SAMLObject<Assertion> desAssertion = (SAMLObject<Assertion>) input.readObject();

        assertEquals("testID", desAssertion.getObject().getID());

        // And for the second time, as we cache some data
        outStream = new ByteArrayOutputStream();
        stream = new ObjectOutputStream(outStream);
        stream.writeObject(assertionObject);

        inputStream = new ByteArrayInputStream(outStream.toByteArray());
        input = new ObjectInputStream(inputStream);
        desAssertion = (SAMLObject<Assertion>) input.readObject();

        assertEquals("testID", desAssertion.getObject().getID());
    }
}