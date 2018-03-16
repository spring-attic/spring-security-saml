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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.entity.ContentType;
import org.opensaml.compat.transport.http.HTTPInTransport;
import org.opensaml.security.credential.Credential;
import org.springframework.http.HttpMethod;

/**
 * Implementation of HTTPInTransport delegating to a HTTPClient postMethod object.
 *
 * @author Mandus Elfving, Vladimir Schafer
 */
public class HttpClientInTransport implements HTTPInTransport, LocationAwareInTransport {

    private final HttpResponse postMethod;
    private final String endpointURI;

    public HttpClientInTransport(HttpResponse postMethod, String endpointURI) {
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
            return postMethod.getEntity().getContent();
        } catch (IOException ioe) {
            return null;
        }
    }

    public Object getAttribute(String s) {
        return null;
    }

    public String getCharacterEncoding() {
        return ContentType.getOrDefault(postMethod.getEntity()).getCharset().toString();
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
        return HttpMethod.POST.name();
    }

    public int getStatusCode() {
        return postMethod.getStatusLine().getStatusCode();
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
