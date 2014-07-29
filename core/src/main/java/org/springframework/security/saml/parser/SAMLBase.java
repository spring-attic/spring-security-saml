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

import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.Reader;
import java.io.Serializable;

/**
 * Base class for implementing holders for XML objects capable of serialization.
 *
 * @author Vladimir Schafer
 */
public abstract class SAMLBase<T extends XMLObject, U> implements Serializable {

    protected final static Logger log = LoggerFactory.getLogger(SAMLBase.class);

    /**
     * Version of the value stored within object transferable during serialization.
     */
    protected Serializable serializedObject;

    /**
     * Parsed instance.
     */
    protected transient U object;

    /**
     * Hash of the object.
     */
    private int hashCode;

    /**
     * Default constructor.
     *
     * @param object object to be stored within object and made serializable
     */
    protected SAMLBase(U object) {
        if (object == null) {
            throw new IllegalArgumentException("SAMLBase object can't be created with null object argument");
        }
        this.object = object;
        this.hashCode = object.hashCode();
    }

    /**
     * @return stored object in non-serialized format
     */
    public U getObject() {
        return object;
    }

    /**
     * Helper method that deserializes and unmarshalls the message from the given stream.
     *
     * @param messageStream input stream containing the message
     *
     * @return the inbound message
     *
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException
     *          thrown if there is a problem deserializing and unmarshalling the message
     */
    protected T unmarshallMessage(Reader messageStream) throws MessageDecodingException {
        log.debug("Parsing message stream into DOM document");

        try {
            Document messageDoc = getPool().parse(messageStream);
            Element messageElem = messageDoc.getDocumentElement();

            if (log.isTraceEnabled()) {
                log.trace("Unmarshalled message into DOM:\n{}", XMLHelper.nodeToString(messageElem));
            }

            log.debug("Unmarshalling message DOM");
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(messageElem);
            if (unmarshaller == null) {
                throw new MessageDecodingException(
                        "Unable to unmarshall message, no unmarshaller registered for message element "
                        + XMLHelper.getNodeQName(messageElem));
            }

            T message = (T) unmarshaller.unmarshall(messageElem);

            log.debug("Message successfully unmarshalled");
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
        return ParserPoolHolder.getPool();
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SAMLBase that = (SAMLBase) o;

        if (serializedObject != null && that.serializedObject != null) {
            // If both objects were already serialized let's compare the serialized versions
            return serializedObject.equals(that.serializedObject);
        } else {
            // Otherwise let's compare the live values
            return object != null && object.equals(that.object);
        }

    }

    @Override
    public int hashCode() {
        return hashCode;
    }

}