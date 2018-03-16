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

import org.opensaml.compat.transport.OutTransport;

/**
 * HTTP-based outbound transport.
 */
public interface HTTPOutTransport extends OutTransport, HTTPTransport {

    /**
     * Sets the HTTP version to use for outgoing messages.
     *
     * @param version HTTP version to use for outgoing messages
     */
    public void setVersion(HTTP_VERSION version);

    /**
     * Sets the given header with the given value.
     *
     * @param name header name
     * @param value header value
     */
    public void setHeader(String name, String value);

    /**
     * Sets the given parameter with the given value.
     *
     * @param name parameter name
     * @param value parameter value
     */
    public void addParameter(String name, String value);

    /**
     * Sets the status code for this transport.
     *
     * @param code status code for this transport
     */
    public void setStatusCode(int code);

    /**
     * Sends an HTTP 3XX redirect message back to the client.
     *
     * @param location location to redirect the client to
     */
    public void sendRedirect(String location);
}
