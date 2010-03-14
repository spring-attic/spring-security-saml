/*
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
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * SAMLCollection is a wrapper around a collection od XMLObject instances of OpenSAML library As some collections of
 * XMLObjects are stored inside the HttpSession (which could be potentially sent to another cluster member), we need
 * mechanism to enable serialization of these instances.
 *
 * @author Mandus Elfving, Vladimir Schafer
 */
public class SAMLCollection<T extends XMLObject> extends SAMLBase<T, List<T>> {

    /**
     * Default constructor.
     *
     * @param object list of objects to wrap with serialization logic
     */
    public SAMLCollection(List<T> object) {
        super(object);
    }

    /**
     * Custom serialization logic which transform List of XMLObject into List of Strings.
     *
     * @param out output stream
     * @throws java.io.IOException error performing XMLObject serialization
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        try {
            if (serializedObject == null) {
                ArrayList<String> serializedItems = new ArrayList<String>();
                for (T item : getObject()) {
                    serializedItems.add(XMLHelper.nodeToString(marshallMessage(item)));
                }
                serializedObject = serializedItems;
            }
            out.writeObject(serializedObject);
        } catch (MessageEncodingException e) {
            log.error("Error serializing SAML object", e);
            throw new IOException("Error serializing SAML object");
        }
    }

    /**
     * Deserializes List of XMLObjects from the stream.
     *
     * @param in input stream containing XMLObject as String
     * @throws IOException            error deserializing String to XMLObject
     * @throws ClassNotFoundException class not found
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            ArrayList<String> serializedItems = (ArrayList<String>) in.readObject();
            List<T> items = new LinkedList<T>();
            for (String item : serializedItems) {
                items.add(unmarshallMessage(new StringReader(item)));
            }
            this.serializedObject = serializedItems;
            object = items;
        } catch (MessageDecodingException e) {
            log.error("Error de-serializing SAML object", e);
            throw new IOException("Error de-serializing SAML object");
        }
    }

 }