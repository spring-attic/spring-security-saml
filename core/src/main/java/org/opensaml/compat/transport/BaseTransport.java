/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat.transport;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.security.credential.Credential;

/**
 * Base abstract class for a {@link Transport} that provides local storage for all transport properties.
 */
public abstract class BaseTransport implements Transport {

    /** Local credential. */
    private Credential localCredential;

    /** Peer credential. */
    private Credential peerCredential;

    /** Transport attributes. */
    private Map<String, Object> attributes;

    /** Character encoding. */
    private String characterEncoding;

    /** Authenticated flag. */
    private boolean authenticated;

    /** Confidential flag. */
    private boolean confidential;

    /** Integrity-protected flag. */
    private boolean integrityProtected;

    /** Constructor. */
    public BaseTransport() {
        attributes = new HashMap<String, Object>();
    }

    /** {@inheritDoc} */
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    /** {@inheritDoc} */
    public String getCharacterEncoding() {
        return characterEncoding;
    }

    /** {@inheritDoc} */
    public Credential getLocalCredential() {
        return localCredential;
    }

    /** {@inheritDoc} */
    public Credential getPeerCredential() {
        return peerCredential;
    }

    /** {@inheritDoc} */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /** {@inheritDoc} */
    public boolean isConfidential() {
        return confidential;
    }

    /** {@inheritDoc} */
    public boolean isIntegrityProtected() {
        return integrityProtected;
    }

    /** {@inheritDoc} */
    public void setAuthenticated(boolean isAuthenticated) {
        authenticated = isAuthenticated;
    }

    /** {@inheritDoc} */
    public void setConfidential(boolean isConfidential) {
        confidential = isConfidential;
    }

    /** {@inheritDoc} */
    public void setIntegrityProtected(boolean isIntegrityProtected) {
        integrityProtected = isIntegrityProtected;
    }

    /**
     * Set an attribute value.
     *
     * @param name attribute name
     * @param value attribute value
     */
    protected void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }

    /**
     * Set the character encoding.
     *
     * @param encoding the character encoding
     */
    protected void setCharacterEncoding(String encoding) {
        characterEncoding = encoding;
    }

}
