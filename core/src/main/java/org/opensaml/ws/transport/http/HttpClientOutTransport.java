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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.List;

import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.AbstractHttpEntity;
import org.apache.http.params.HttpParams;
import org.opensaml.compat.transport.http.HTTPOutTransport;
import org.opensaml.compat.transport.http.HTTPTransport;
import org.opensaml.security.credential.Credential;
import org.opensaml.ws.transport.http.httpclient.OutputStreamRequestEntity;

/**
 * Implementation of HTTPOutTransport delegating to a HTTPClient PortMethod object.
 *
 * @author Mandus Elfving
 */
public class HttpClientOutTransport implements HTTPOutTransport {

    private final HttpPost postMethod;

    public HttpClientOutTransport(HttpPost postMethod) {
        this.postMethod = postMethod;
    }

    public void setVersion(HTTP_VERSION http_version) {
        HttpParams params = postMethod.getParams();

        switch (http_version) {
            case HTTP1_0:
                params.setParameter("http.protocol.version", HttpVersion.HTTP_1_0);
                break;
            case HTTP1_1:
                params.setParameter("http.protocol.version", HttpVersion.HTTP_1_1);
                break;
        }
    }

    public void setHeader(String s, String s1) {
        postMethod.addHeader(s, s1);
    }

    public void addParameter(String s, String s1) {

    }

    public void setStatusCode(int i) {

    }

    public void sendRedirect(String s) {

    }

    public void setAttribute(String s, Object o) {

    }

    public void setCharacterEncoding(String s) {
        postMethod.getParams().setParameter("http.protocol.content-charset", s);
    }

    public OutputStream getOutgoingStream() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        AbstractHttpEntity requestEntity = new OutputStreamRequestEntity(outputStream);
        postMethod.setEntity(requestEntity);
        return outputStream;
    }

    public Object getAttribute(String s) {
        return null;
    }

    public String getCharacterEncoding() {
        return postMethod("http.protocol.content-charset").getValue();
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
        return postMethod.getRequestHeader(s).getValue();
    }

    public String getHTTPMethod() {
        return postMethod.getParameter("http.protocol.version").getValue();
    }

    public int getStatusCode() {
        return -1;
    }

    public String getParameterValue(String s) {
        return null;
    }

    public List<String> getParameterValues(String s) {
        return null;
    }

    public HTTPTransport.HTTP_VERSION getVersion() {
        HttpVersion httpVersion = (HttpVersion) postMethod.getParams().getParameter("http.protocol.version");

        if (httpVersion == HttpVersion.HTTP_1_1) {
            return HTTPTransport.HTTP_VERSION.HTTP1_1;
        }

        return HTTP_VERSION.HTTP1_0;
    }
}
