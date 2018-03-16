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

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

import org.opensaml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapts an {@link HttpServletResponse} to an {@link HTTPOutTransport}.
 */
public class HttpServletResponseAdapter implements HTTPOutTransport {

    /** Adapted servlet response. */
    private HttpServletResponse httpServletResponse;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HttpServletResponseAdapter.class);

    /** Whether the peer endpoint has been authenticated. */
    private boolean peerAuthenticated;

    /** Whether the HTTP connection is over SSL/TLS. */
    private boolean secure;

    /**
     * Constructor.
     *
     * @param response servlet response to adapt
     * @param isSecure whether the outbound connection is protected by SSL/TLS
     */
    public HttpServletResponseAdapter(HttpServletResponse response, boolean isSecure) {
        httpServletResponse = response;
        secure = isSecure;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation and always returns null.
     */
    public Object getAttribute(String name) {
        return null;
    }

    /** {@inheritDoc} */
    public String getCharacterEncoding() {
        return httpServletResponse.getCharacterEncoding();
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     *
     */
    public String getHeaderValue(String name) {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public String getHTTPMethod() {
        return null;
    }

    /** {@inheritDoc} */
    public Credential getLocalCredential() {
        // TODO Auto-generated method stub
        return null;
    }

    /** {@inheritDoc} */
    public OutputStream getOutgoingStream() {
        try {
            return httpServletResponse.getOutputStream();
        } catch (IOException e) {
            log.error("Unable to recover input stream from adapted HttpServletResponse", e);
            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public String getParameterValue(String name) {
        return null;
    }

    /** {@inheritDoc} */
    public List<String> getParameterValues(String name) {
        return null;
    }

    /** {@inheritDoc} */
    public Credential getPeerCredential() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public int getStatusCode() {
        return -1;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public HTTP_VERSION getVersion() {
        return null;
    }

    /**
     * Gets the adapted response.
     *
     * @return adapted response
     */
    public HttpServletResponse getWrappedResponse() {
        return httpServletResponse;
    }

    /** {@inheritDoc} */
    public boolean isAuthenticated() {
        return peerAuthenticated;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation and always returns false.
     */
    public boolean isConfidential() {
        return secure;
    }

    /** {@inheritDoc} */
    public void sendRedirect(String location) {
        try {
            httpServletResponse.sendRedirect(location);
        } catch (IOException e) {
            log.error("Unable to send redirect message", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public void setAttribute(String name, Object value) {
    }

    /**
     * {@inheritDoc}
     */
    public void setAuthenticated(boolean isAuthenticated) {
        peerAuthenticated = isAuthenticated;
    }

    /** {@inheritDoc} */
    public void setCharacterEncoding(String encoding) {
        httpServletResponse.setCharacterEncoding(encoding);
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public void setConfidential(boolean isConfidential) {
    }

    /** {@inheritDoc} */
    public void setHeader(String name, String value) {
        if (name == null) {
            return;
        }

        // HttpServletRequest requires certain headers be set by special methods
        if (name.equalsIgnoreCase("Content-Type")) {
            httpServletResponse.setContentType(value);
        } else if (name.equalsIgnoreCase("Content-Length")) {
            httpServletResponse.setContentLength(Integer.parseInt(value));
        }

        httpServletResponse.setHeader(name, value);
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public void addParameter(String name, String value) {
    }

    /** {@inheritDoc} */
    public void setStatusCode(int code) {
        httpServletResponse.setStatus(code);
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public void setVersion(HTTP_VERSION version) {
    }

    /** {@inheritDoc} */
    public boolean isIntegrityProtected() {
        return secure;
    }

    /** {@inheritDoc} */
    public void setIntegrityProtected(boolean isIntegrityProtected) {

    }
}