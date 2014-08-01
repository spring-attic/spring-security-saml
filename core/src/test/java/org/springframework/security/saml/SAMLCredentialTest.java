/* Copyright 2009 Vladimir Schafer
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
package org.springframework.security.saml;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.runner.RunWith;
import org.opensaml.common.BaseTestCase;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

/**
 * @author Vladimir Schafer
 */
@RunWith(JUnit4ClassRunner.class)
public class SAMLCredentialTest extends BaseTestCase {

    SAMLCredential credential;
    NameID nameID;
    Assertion assertion;

    @Before
    public void initializeValues() throws Exception {
        super.setUp();
        nameID = ((SAMLObjectBuilder<NameID>) SAMLTestHelper.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
        assertion = ((SAMLObjectBuilder<Assertion>) SAMLTestHelper.getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME)).buildObject();
        nameID.setValue("testName");
        assertion.setID("testID");
        credential = new SAMLCredential(nameID, assertion, "testIDP", "testSP");
    }

    @After
    public void stopTest() throws Exception {
        super.tearDown();
    }

    /**
     * Verifies that initial values are set as expected.
     */
    @Test
    public void testInitialization() {
        assertNotNull(credential.getNameID());
        assertNotNull(credential.getAuthenticationAssertion());
        assertEquals("testName", credential.getNameID().getValue());
        assertEquals("testID", credential.getAuthenticationAssertion().getID());
        assertEquals("testIDP", credential.getRemoteEntityID());
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
        stream.writeObject(credential);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(outStream.toByteArray());
        ObjectInputStream input = new ObjectInputStream(inputStream);
        SAMLCredential desCredential = (SAMLCredential) input.readObject();

        assertEquals("testName", desCredential.getNameID().getValue());
        assertEquals("testID", desCredential.getAuthenticationAssertion().getID());
    }

    /**
     * Verifies that attributes can be loaded from the assertion.
     *
     * @throws Exception error
     */
    @Test
    public void testAttributes() throws Exception {

        String assertionFile = "/testResponse_01.xml";
        Response response = (Response) unmarshallElement(assertionFile);

        Assertion assertion = response.getAssertions().iterator().next();
        List<AttributeStatement> statements = assertion.getAttributeStatements();
        List<Attribute> attributes = new ArrayList<Attribute>();
        for (AttributeStatement statement : statements) {
            attributes.addAll(statement.getAttributes());
        }

        credential = new SAMLCredential(assertion.getSubject().getNameID(), assertion, "entity", "relayState", attributes, "local");

        // Attribute with a single value
        assertEquals("vladimir@v7security.com", credential.getAttributeAsString("emailAddress"));
        assertArrayEquals(new String[] {"vladimir@v7security.com"}, credential.getAttributeAsStringArray("emailAddress"));

        // Attribute with a single value, without declared type
        assertEquals("Vladimir", credential.getAttributeAsString("FirstName"));
        assertArrayEquals(new String[] {"Vladimir"}, credential.getAttributeAsStringArray("FirstName"));

        // Attribute existing multiple times
        assertNotNull(credential.getAttribute("LastName"));
        assertNotNull(credential.getAttribute("lastName"));
        assertEquals("Schafer", credential.getAttributeAsString("LastName"));
        assertArrayEquals(new String[] {"Schafer", "Schafer2"}, credential.getAttributeAsStringArray("LastName"));

        // Non-existent attribute
        assertNull(credential.getAttributeAsString("abc"));
        assertNull(credential.getAttributeAsStringArray("abc"));

        // Custom attribute
        Attribute special = credential.getAttribute("special");
        assertNotNull(special);
        assertNull(credential.getAttributeAsString("special"));
        assertEquals(1, special.getDOM().getElementsByTagName("test").getLength());
        assertArrayEquals(new String[] {null, "xyz", null}, credential.getAttributeAsStringArray("special"));

    }

}
