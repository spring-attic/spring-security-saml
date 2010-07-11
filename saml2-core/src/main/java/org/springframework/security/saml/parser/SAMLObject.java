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
package org.springframework.security.saml.parser;

import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;

/**
 * SAMLObject is a wrapper around XMLObject instances of OpenSAML library As some XMLObjects are stored
 * inside the HttpSession (which could be potentially sent to another cluster members), we need
 * mechanism to enable serialization of these instances.
 *
 * @author Vladimir Schafer
 * @param <T> type of XMLObject
 */
public class SAMLObject<T extends XMLObject> extends SAMLBase<T, T> {

    /**
     * Default constructor.
     *
     * @param object object to wrap with serialization logic
     */
    public SAMLObject(T object) {
        super(object);
    }

    @Override
    public T getObject() {
        return super.getObject();
    }

    /**
     * Custom serialization logic which transform XMLObject into String.
     *
     * @param out output stream
     *
     * @throws java.io.IOException error performing XMLObject serialization
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        try {
            if (serializedObject == null) {
                serializedObject = XMLHelper.nodeToString(marshallMessage(getObject()));
            }
            out.writeUTF((String) serializedObject);
        } catch (MessageEncodingException e) {
            log.error("Error serializing SAML object", e);
            throw new IOException("Error serializing SAML object: " + e.getMessage());
        }
    }

    /**
     * Deserializes XMLObject from the stream.
     *
     * @param in input stream contaiing XMLObject as String
     *
     * @throws IOException            error deserializing String to XMLObject
     * @throws ClassNotFoundException class not found
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            serializedObject = in.readUTF();
            object = unmarshallMessage(new StringReader((String) serializedObject));
        } catch (MessageDecodingException e) {
            log.error("Error de-serializing SAML object", e);
            throw new IOException("Error de-serializing SAML object: " + e.getMessage());
        }
    }
}