/* Copyright 2009 Vladimir Schäfer
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
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.storage.HttpSessionStorage;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.*;

/**
 * SAMLObject is a wrapper around XMLObject instances of OpenSAML library As some XMLObjects are stored
 * inside the HttpSession (which could be potentially sent to another cluster members), we need
 * mechanism to enable serialization of these instances.
 *
 * @param <T> type of XMLObject
 *
 * @author Vladimir Schäfer
 */
public class SAMLObject<T extends XMLObject> implements Serializable {

    protected final static Logger log = LoggerFactory.getLogger(HttpSessionStorage.class);

    private String serializedObject;

    private T object;

    /**
     * Default constructor.
     *
     * @param object object to wrap with serialization logic
     */
    public SAMLObject(T object) {
        if (object == null) {
            throw new IllegalArgumentException("SAMLObject can't be created with null object argument");
        }
        this.object = object;
    }

    /**
     * @return wrapped object.
     */
    public T getObject() {
        return object;
    }

    /**
     * Helper method that marshalls the given message.
     *
     * @param message message the marshall and serialize
     * @return marshalled message
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException
     *          thrown if the give message can not be marshalled into its DOM representation
     */
    protected Element marshallMessage(T message) throws MessageEncodingException {
        log.debug("Marshalling message");
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(message);
            if (marshaller == null) {
                throw new MessageEncodingException("Unable to marshall message, no marshaller registered for message object: "
                        + message.getElementQName());
            }
            Element messageElem = marshaller.marshall(message);
            if (log.isTraceEnabled()) {
                log.trace("Marshalled message into DOM:\n{}", XMLHelper.nodeToString(messageElem));
            }
            return messageElem;
        } catch (MarshallingException e) {
            log.error("Encountered error marshalling message to its DOM representation", e);
            throw new MessageEncodingException("Encountered error marshalling message into its DOM representation", e);
        }
    }

    /**
     * Helper method that deserializes and unmarshalls the message from the given stream.
     *
     * @param messageStream input stream containing the message
     * @return the inbound message
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException
     *          thrown if there is a problem deserializing and unmarshalling the message
     */
    protected T unmarshallMessage(Reader messageStream) throws MessageDecodingException {
        log.debug("Parsing message stream into DOM document");

        try {
            Document messageDoc = getPool().parse(messageStream);
            Element messageElem = messageDoc.getDocumentElement();

            if (log.isTraceEnabled()) {
                log.trace("Unmrshalled message into DOM:\n{}", XMLHelper.nodeToString(messageElem));
            }

            log.debug("Unmarshalling message DOM");
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(messageElem);
            if (unmarshaller == null) {
                throw new MessageDecodingException(
                        "Unable to unmarshall message, no unmarshaller registered for message element "
                                + XMLHelper.getNodeQName(messageElem));
            }

            T message = (T) unmarshaller.unmarshall(messageElem);

            log.debug("Message succesfully unmarshalled");
            return message;
        } catch (XMLParserException e) {
            log.error("Encountered error parsing message into its DOM representation", e);
            throw new MessageDecodingException("Encountered error parsing message into its DOM representation", e);
        } catch (UnmarshallingException e) {
            log.error("Encountered error unmarshalling message from its DOM representation", e);
            throw new MessageDecodingException("Encountered error unmarshalling message from its DOM representation", e);
        }
    }

    private ParserPool getPool() throws MessageDecodingException {
        ParserPool pool = ParserPoolHolder.getPool();
        if (pool == null) {
            throw new MessageDecodingException("Parser pool holder wasn't initialized");
        }
        return pool;
    }

    /**
     * Custom serialization logic which transform XMLObject into String.
     *
     * @param out output stream
     * @throws java.io.IOException error performing XMLObject serialization
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        try {
            if (serializedObject == null) {
                serializedObject = XMLHelper.nodeToString(marshallMessage(getObject()));
            }
            out.writeUTF(serializedObject);
        } catch (MessageEncodingException e) {
            log.error("Error serializing SAML object", e);
            throw new IOException("Error serializing SAML object");
        }
    }

    /**
     * Deserializes XMLObject from the stream.
     *
     * @param in input stream contaiing XMLObject as String
     * @throws IOException            error deserializing String to XMLObject
     * @throws ClassNotFoundException class not found
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            serializedObject = in.readUTF();
            object = unmarshallMessage(new StringReader(serializedObject));
        } catch (MessageDecodingException e) {
            log.error("Error de-serializing SAML object", e);
            throw new IOException("Error de-serializing SAML object");
        }
    }

}