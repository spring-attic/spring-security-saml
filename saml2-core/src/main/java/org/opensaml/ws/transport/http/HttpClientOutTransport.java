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

import org.apache.commons.httpclient.HttpVersion;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.params.HttpParams;
import org.opensaml.ws.transport.http.httpclient.OutputStreamRequestEntity;
import org.opensaml.xml.security.credential.Credential;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Implementation of HTTPOutTransport delegating to a HTTPClient PortMethod object.
 *
 * @author Mandus Elfving
 */
public class HttpClientOutTransport implements HTTPOutTransport {

    private final PostMethod postMethod;

    public HttpClientOutTransport(PostMethod postMethod) {
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
        postMethod.setRequestHeader(s, s1);
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
        RequestEntity requestEntity = new OutputStreamRequestEntity(outputStream);

        postMethod.setRequestEntity(requestEntity);

        return outputStream;
    }

    public Object getAttribute(String s) {
        return null;
    }

    public String getCharacterEncoding() {
        return postMethod.getParameter("http.protocol.content-charset").getValue();
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

    public HTTP_VERSION getVersion() {
        HttpVersion httpVersion = (HttpVersion) postMethod.getParams().getParameter("http.protocol.version");

        if (httpVersion == HttpVersion.HTTP_1_1) {
            return HTTP_VERSION.HTTP1_1;
        }

        return HTTP_VERSION.HTTP1_0;
    }
}
