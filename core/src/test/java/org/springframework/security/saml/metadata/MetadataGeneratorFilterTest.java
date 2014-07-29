/* Copyright 2009 Vladimir Schäfer
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
package org.springframework.security.saml.metadata;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;

import static junit.framework.Assert.assertEquals;

/**
 * Test for metadata generator.
 */
public class MetadataGeneratorFilterTest {

    private MockHttpServletRequest httpRequest;
    private MetadataGeneratorFilter filter;

    @Before
    public void init() {
        httpRequest = new MockHttpServletRequest();
        filter = new MetadataGeneratorFilter(new MetadataGenerator());
    }

    /**
     * Test that normalization is disabled by default.
     */
    @Test
    public void testDefaultBaseUrlDefault() {
        httpRequest.setServerName("testServer");
        httpRequest.setScheme("HTTP");
        httpRequest.setContextPath("/myContext");
        httpRequest.setServerPort(80);
        String baseURL = filter.getDefaultBaseURL(httpRequest);
        assertEquals("HTTP://testServer:80/myContext", baseURL);
    }

    @Test
    public void testDefaultBaseUrlDefaultPort() {
        filter.setNormalizeBaseUrl(false);
        httpRequest.setServerName("testServer");
        httpRequest.setScheme("HTTP");
        httpRequest.setContextPath("/myContext");
        httpRequest.setServerPort(80);
        String baseURL = filter.getDefaultBaseURL(httpRequest);
        assertEquals("HTTP://testServer:80/myContext", baseURL);
    }

    @Test
    public void testDefaultBaseUrlNormalizeDefaultPort() {
        filter.setNormalizeBaseUrl(true);
        httpRequest.setServerName("testServer");
        httpRequest.setScheme("http");
        httpRequest.setContextPath("/myContext");
        httpRequest.setServerPort(80);
        String baseURL = filter.getDefaultBaseURL(httpRequest);
        assertEquals("http://testserver/myContext", baseURL);
    }

    @Test
    public void testDefaultBaseUrlNormalizeCustomPort() {
        filter.setNormalizeBaseUrl(true);
        httpRequest.setServerName("testServer");
        httpRequest.setScheme("http");
        httpRequest.setContextPath("/myContext");
        httpRequest.setServerPort(81);
        String baseURL = filter.getDefaultBaseURL(httpRequest);
        assertEquals("http://testserver:81/myContext", baseURL);
    }

    @Test
    public void testDefaultBaseUrlNormalizeSSL() {
        filter.setNormalizeBaseUrl(true);
        httpRequest.setServerName("testServer");
        httpRequest.setScheme("https");
        httpRequest.setContextPath("/myContext");
        httpRequest.setServerPort(443);
        String baseURL = filter.getDefaultBaseURL(httpRequest);
        assertEquals("https://testserver/myContext", baseURL);
    }

    @Test
    public void testDefaultBaseUrlNormalizeNoSSL443() {
        filter.setNormalizeBaseUrl(true);
        httpRequest.setServerName("testServer");
        httpRequest.setScheme("http");
        httpRequest.setContextPath("/myContext");
        httpRequest.setServerPort(443);
        String baseURL = filter.getDefaultBaseURL(httpRequest);
        assertEquals("http://testserver:443/myContext", baseURL);
    }

}
