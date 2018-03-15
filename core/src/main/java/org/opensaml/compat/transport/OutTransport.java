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

import java.io.OutputStream;

/**
 * Represents an outbound transport, that is the transport used to send information.
 */
public interface OutTransport extends Transport {

    /**
     * Sets a transport-specific attribute.
     *
     * @param name attribute name
     * @param value attribute value
     */
    public void setAttribute(String name, Object value);

    /**
     * Sets the character encoding of the transport.
     *
     * @param encoding character encoding of the transport
     */
    public void setCharacterEncoding(String encoding);

    /**
     * Gets the outgoing data stream to the peer.
     *
     * @return outgoing data stream to the peer
     */
    public OutputStream getOutgoingStream();
}