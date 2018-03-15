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

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.ws.security.ServletRequestX509CredentialAdapter;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapts an {@link HttpServletRequest} to an {@link HTTPInTransport}.
 */
public class HttpServletRequestAdapter implements HTTPInTransport {

    /** Adapted servlet request. */
    private HttpServletRequest httpServletRequest;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HttpServletRequestAdapter.class);

    /** Whether the peer endpoint has been authenticated. */
    private boolean peerAuthenticated;

    /** Storage for peer credential adapted from HTTP servlet request. */
    private Credential peerCredential;

    /**
     * Constructor.
     *
     * @param request servlet request to adap
     */
    public HttpServletRequestAdapter(HttpServletRequest request) {
        httpServletRequest = request;
    }

    /** {@inheritDoc} */
    public Object getAttribute(String name) {
        return httpServletRequest.getAttribute(name);
    }

    /** {@inheritDoc} */
    public String getCharacterEncoding() {
        return httpServletRequest.getCharacterEncoding();
    }

    /** {@inheritDoc} */
    public String getHeaderValue(String name) {
        // This appears to be necessary for at least some HttpServletRequest impls
        if (name.equalsIgnoreCase("Content-Type")) {
            return httpServletRequest.getContentType();
        } else if (name.equalsIgnoreCase("Content-Length")) {
            return Integer.toString(httpServletRequest.getContentLength());
        }
        return httpServletRequest.getHeader(name);
    }

    /** {@inheritDoc} */
    public String getHTTPMethod() {
        return httpServletRequest.getMethod();
    }

    /** {@inheritDoc} */
    public InputStream getIncomingStream() {
        try {
            return httpServletRequest.getInputStream();
        } catch (IOException e) {
            log.error("Unable to recover input stream from adapted HttpServletRequest", e);
            return null;
        }
    }

    /** {@inheritDoc} */
    public Credential getLocalCredential() {
        // TODO Auto-generated method stub
        return null;
    }

    /** {@inheritDoc} */
    public String getParameterValue(String name) {
        return httpServletRequest.getParameter(name);

    }

    /** {@inheritDoc} */
    public List<String> getParameterValues(String name) {
        ArrayList<String> valuesList = new ArrayList<String>();
        String[] values = httpServletRequest.getParameterValues(name);
        if (values != null) {
            for (String value : values) {
                valuesList.add(value);
            }
        }

        return valuesList;
    }

    /** {@inheritDoc} */
    public String getPeerAddress() {
        return httpServletRequest.getRemoteAddr();
    }

    /** {@inheritDoc} */
    public Credential getPeerCredential() {
        if (peerCredential == null) {
            try {
                peerCredential = new ServletRequestX509CredentialAdapter(httpServletRequest);
            } catch (IllegalArgumentException e) {
                log.info("Wrapped HTTP servlet request did not contain a client certificate");
            }
        }
        return peerCredential;
    }

    /** {@inheritDoc} */
    public String getPeerDomainName() {
        return httpServletRequest.getRemoteHost();
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation. It always returns -1;
     */
    public int getStatusCode() {
        return -1;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation. It always returns null;
     */
    public HTTP_VERSION getVersion() {
        // unsupported options
        return null;
    }

    /**
     * Gets the adapted request.
     *
     * @return adapted request
     */
    public HttpServletRequest getWrappedRequest() {
        return httpServletRequest;
    }

    /** {@inheritDoc} */
    public boolean isAuthenticated() {
        return peerAuthenticated;
    }

    /** {@inheritDoc} */
    public boolean isConfidential() {
        return httpServletRequest.isSecure();
    }

    /** {@inheritDoc} */
    public void setAuthenticated(boolean isAuthenticated) {
        peerAuthenticated = isAuthenticated;
    }

    /**
     * {@inheritDoc}
     *
     * This method is not supported for this transport implementation.
     */
    public void setConfidential(boolean isConfidential) {

    }

    /** {@inheritDoc} */
    public boolean isIntegrityProtected() {
        return httpServletRequest.isSecure();
    }

    /** {@inheritDoc} */
    public void setIntegrityProtected(boolean isIntegrityProtected) {

    }
}