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

import java.util.List;

import org.opensaml.ws.transport.Transport;

/**
 * An HTTP-based transport.
 */
public interface HTTPTransport extends Transport {

    /** HTTP version identifier. */
    public static enum HTTP_VERSION {
        /** HTTP version 1.0. */
        HTTP1_0,

        /** HTTP version 1.1. */
        HTTP1_1,
    };

    /**
     * Gets the first value of the header with the given name.
     *
     * @param name header name
     *
     * @return first value of the header with the given name, or null
     */
    public String getHeaderValue(String name);

    /**
     * Gets the HTTP method (POST, GET, etc) used.
     *
     * @return HTTP method used
     */
    public String getHTTPMethod();

    /**
     * Gets the status code of the request.
     *
     * @return status code of the request
     */
    public int getStatusCode();

    /**
     * Gets the first value of the named parameter. If the request is GET, this is a decoded URL parameter.
     * If the request is POST-based, it is a parameter from the POST body.
     *
     * @param name parameter name
     *
     * @return parameter value
     */
    public String getParameterValue(String name);

    /**
     * Gets the values of the named parameter. If the request is GET, this is a decoded URL parameter.
     * If the request is POST-based, it is a parameter from the POST body.
     *
     * @param name parameter name
     *
     * @return parameter values
     */
    public List<String> getParameterValues(String name);

    /**
     * Gets the HTTP version used to receive the message.
     *
     * @return HTTP version used to receive the message
     */
    public HTTP_VERSION getVersion();
}
