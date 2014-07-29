/*
 * Copyright 2010 Mandus Elfving
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
package org.opensaml.ws.transport.http;

import org.apache.commons.httpclient.methods.PostMethod;
import org.opensaml.xml.security.credential.Credential;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * Implementation of HTTPInTransport delegating to a HTTPClient postMethod object.
 *
 * @author Mandus Elfving, Vladimir Schafer
 */
public class HttpClientInTransport implements HTTPInTransport, LocationAwareInTransport {

    private final PostMethod postMethod;
    private final String endpointURI;

    public HttpClientInTransport(PostMethod postMethod, String endpointURI) {
        this.postMethod = postMethod;
        this.endpointURI = endpointURI;
    }

    public String getLocalAddress() {
        return endpointURI;
    }

    public String getPeerAddress() {
        return null;
    }

    public String getPeerDomainName() {
        return null;
    }

    public InputStream getIncomingStream() {
        try {
            return postMethod.getResponseBodyAsStream();
        } catch (IOException ioe) {
            return null;
        }
    }

    public Object getAttribute(String s) {
        return null;
    }

    public String getCharacterEncoding() {
        return postMethod.getResponseCharSet();
    }

    public Credential getLocalCredential() {
        return null;
    }

    public Credential getPeerCredential() {
        return null;
    }

    public boolean isAuthenticated() {
        return false;
    }

    public void setAuthenticated(boolean b) {

    }

    public boolean isConfidential() {
        return false;
    }

    public void setConfidential(boolean b) {

    }

    public boolean isIntegrityProtected() {
        return false;
    }

    public void setIntegrityProtected(boolean b) {

    }

    public String getHeaderValue(String s) {
        return null;
    }

    public String getHTTPMethod() {
        return postMethod.getName();
    }

    public int getStatusCode() {
        return postMethod.getStatusCode();
    }

    public String getParameterValue(String s) {
        return null;
    }

    public List<String> getParameterValues(String s) {
        return null;
    }

    public HTTP_VERSION getVersion() {
        return null;
    }
}
