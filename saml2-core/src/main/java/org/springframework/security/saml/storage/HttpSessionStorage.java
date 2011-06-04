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
package org.springframework.security.saml.storage;

import org.opensaml.xml.XMLObject;
import org.springframework.security.saml.parser.SAMLObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Set;

/**
 * Class implements storage of SAML messages and uses HttpSession as underlying dataStore. As the XMLObjects
 * can't be serialized and failover could thus be prevented, the messages are transformed into SAMLObject
 * which internally marshalls the content into XML during serialization.
 *
 * @author Vladimir Schäfer
 */
public class HttpSessionStorage implements SAMLMessageStorage {

    private final HttpSession session;
    private Hashtable<String, SAMLObject<XMLObject>> messages;

    private static final String SAML_STORAGE_KEY = "_springSamlStorageKey";

    /**
     * Creates the storage object and initializes it to load SAML messages from Session
     * found in the request object.
     *
     * @param request request to load/store messages from
     */
    public HttpSessionStorage(HttpServletRequest request) {
        this(request.getSession(true));
    }

    public HttpSessionStorage(HttpSession session) {
        this.session = session;
        this.messages = initializeStore();
    }

    /**
     * Call to the method tries to load messages hashtable object from the session, if the object doesn't exist
     * it will be created and stored.
     * <p/>
     * Method synchronizes on session object to prevent two threads from overwriting each others hashtable.
     *
     * @return found/created hashtable.
     */
    private Hashtable<String, SAMLObject<XMLObject>> initializeStore() {
        Hashtable<String, SAMLObject<XMLObject>> messages = (Hashtable<String, SAMLObject<XMLObject>>) session.getAttribute(SAML_STORAGE_KEY);
        if (messages == null) {
            synchronized (session) {
                messages = (Hashtable<String, SAMLObject<XMLObject>>) session.getAttribute(SAML_STORAGE_KEY);
                if (messages == null) {
                    messages = new Hashtable<String, SAMLObject<XMLObject>>();
                    session.setAttribute(SAML_STORAGE_KEY, messages);
                }
            }
        }
        return messages;
    }

    /**
     * Stores a request message into the repository. RequestAbstractType must have an ID
     * set. Any previous message with the same ID will be overwritten.
     *
     * @param id      ID of message
     * @param message message to be stored
     */
    public void storeMessage(String id, XMLObject message) {
        messages.put(id, new SAMLObject<XMLObject>(message));
    }

    /**
     * Returns previously stored message with the given ID or null, if there is no message
     * stored.
     * <p/>
     * Message is stored in String format and must be unmarshalled into XMLObject. Call to this
     * method may thus be expensive.
     *
     * @param messageID ID of message to retrieve
     *
     * @return message found or null
     */
    public XMLObject retrieveMessage(String messageID) {
        SAMLObject o = messages.get(messageID);
        if (o == null) {
            return null;
        } else {
            return o.getObject();
        }
    }

    public Set<String> getAllMessages() {
        return Collections.unmodifiableSet(messages.keySet());
    }
}
