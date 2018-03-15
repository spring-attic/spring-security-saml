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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Utilities for working with HTTP transports.
 */
public class HTTPTransportUtils {

    /** Constructor. */
    protected HTTPTransportUtils() {
    }

    /**
     * Adds Cache-Control and Pragma headers meant to disable caching.
     *
     * @param transport transport to add headers to
     */
    public static void addNoCacheHeaders(HTTPOutTransport transport) {
        transport.setHeader("Cache-control", "no-cache, no-store");
        transport.setHeader("Pragma", "no-cache");
    }

    /**
     * Sets the character encoding of the transport to UTF-8.
     *
     * @param transport transport to set character encoding type
     */
    public static void setUTF8Encoding(HTTPOutTransport transport) {
        transport.setCharacterEncoding("UTF-8");
    }

    /**
     * Sets the MIME content type of the transport.
     *
     * @param transport the transport to set content type on
     * @param contentType the content type to set
     */
    public static void setContentType(HTTPOutTransport transport, String contentType) {
        transport.setHeader("Content-Type", contentType);
    }

    /**
     * URL Decode the given string.
     *
     * @param value the string to decode
     * @return the decoded string
     */
    public static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 encoding is required to be supported by all JVMs
            return null;
        }
    }

    /**
     * URL Encode the given string.
     *
     * @param value the string to encode
     * @return the encoded string
     */
    public static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 encoding is required to be supported by all JVMs
            return null;
        }
    }

    /**
     * Get the first raw (i.e. non URL-decoded) query string component with the specified parameter name.
     *
     * The component will be returned as a string in the form 'paramName=paramValue' (minus the quotes).
     *
     * @param queryString the raw HTTP URL query string
     * @param paramName the name of the parameter to find
     * @return the found component, or null if not found
     */
    public static String getRawQueryStringParameter(String queryString, String paramName) {
        if (queryString == null) {
            return null;
        }

        String paramPrefix = paramName + "=";
        int start = queryString.indexOf(paramPrefix);
        if (start == -1) {
            return null;
        }

        int end = queryString.indexOf('&', start);
        if (end == -1) {
            return queryString.substring(start);
        } else {
            return queryString.substring(start, end);
        }
    }
}