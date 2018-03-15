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

package org.opensaml.compat.transport.http;

import org.opensaml.compat.transport.InTransport;

/**
 * HTTP-based inbound transport.
 *
 * The stream returned by {@link InTransport#getIncomingStream()} represents the body of the HTTP message.
 */
public interface HTTPInTransport extends InTransport, HTTPTransport {

    /**
     * Gets the IP address of the peer.
     *
     * @return IP address of the peer
     */
    public String getPeerAddress();

    /**
     * Gets the domain name of the peer.
     *
     * @return domain name of the peer
     */
    public String getPeerDomainName();
}