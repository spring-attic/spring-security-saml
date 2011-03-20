/* Copyright 2009 Vladimir Sch�fer
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

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;

/**
 * @author Vladimir Sch�fer
 */
public class SAMLCredentialTest extends SAMLTestBase {

    SAMLCredential credential;
    NameID nameID;
    Assertion assertion;

    @Before
    public void initializeValues() {
        nameID = ((SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
        assertion = ((SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME)).buildObject();
        nameID.setValue("testName");
        assertion.setID("testID");
        credential = new SAMLCredential(nameID, assertion, "testIDP", "testSP");
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
}
