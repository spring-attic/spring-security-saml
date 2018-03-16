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

import org.opensaml.security.credential.Credential;

/**
 * Base interface for inbound and outbound transports.
 */
public interface Transport {

    /**
     * Gets a transport-specific attribute.
     *
     * @param name name of the attribute
     *
     * @return attribute value
     */
    public Object getAttribute(String name);

    /**
     * Gets the character encoding of the transport.
     *
     * @return character encoding of the transport
     */
    public String getCharacterEncoding();

    /**
     * Gets the local credential used to authenticate to the peer.
     *
     * @return local credential used to authenticate to the peer
     */
    public Credential getLocalCredential();

    /**
     * Gets the credential offered by the peer to authenticate itself.
     *
     * @return credential offered by the peer to authenticate itself
     */
    public Credential getPeerCredential();

    /**
     * Gets whether the peer is authenticated.
     *
     * @return whether the peer is authenticated
     */
    public boolean isAuthenticated();

    /**
     * Sets whether the peer is authenticated.
     *
     * @param isAuthenticated whether the peer is authenticated
     */
    public void setAuthenticated(boolean isAuthenticated);

    /**
     * Gets whether the transport represents a confidential connection (e.g. an SSL connection).
     *
     * @return whether the transport represents a confidential connection
     */
    public boolean isConfidential();

    /**
     * Sets whether the transport represents a confidential connection.
     *
     * @param isConfidential whether the transport represents a confidential connection
     */
    public void setConfidential(boolean isConfidential);

    /**
     * Gets whether the transport represents a connection that protects the integrity of transported content.
     *
     * @return whether the transport represents a connection that protects the integrity of transported content
     */
    public boolean isIntegrityProtected();

    /**
     * Sets whether the transport represents a connection that protects the integrity of transported content.
     *
     * @param isIntegrityProtected whether the transport represents a connection that protects the integrity of
     *            transported content
     */
    public void setIntegrityProtected(boolean isIntegrityProtected);
}