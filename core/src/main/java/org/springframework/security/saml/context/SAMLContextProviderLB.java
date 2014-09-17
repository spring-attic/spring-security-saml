/*
 * Copyright 2013 Vladimir Schafer
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
package org.springframework.security.saml.context;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

/**
 * Context provider which overrides request attributes with values of the load-balancer or reverse-proxy in front
 * of the local application. The settings help to provide correct redirect URls and verify destination URLs during
 * SAML processing.
 */
public class SAMLContextProviderLB extends SAMLContextProviderImpl {

    private String scheme;
    private String serverName;
    private boolean includeServerPortInRequestURL;
    private int serverPort;
    private String contextPath;

    /**
     * Method wraps the original request and provides values specified for load-balancer. The following methods
     * are overriden: getContextPath, getRequestURL, getRequestURI, getScheme, getServerName, getServerPort and isSecure.
     *
     * @param request  original request
     * @param response response object
     * @param context  context to populate values to
     */
    @Override
    protected void populateGenericContext(HttpServletRequest request, HttpServletResponse response, SAMLMessageContext context) throws MetadataProviderException {

        super.populateGenericContext(new LPRequestWrapper(request), response, context);

    }

    /**
     * Wrapper for original request which overrides values of scheme, server name, server port and contextPath.
     * Method isSecure returns value based on specified scheme.
     */
    private class LPRequestWrapper extends HttpServletRequestWrapper {

        private LPRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getContextPath() {
            return contextPath;
        }

        @Override
        public String getScheme() {
            return scheme;
        }

        @Override
        public String getServerName() {
            return serverName;
        }

        @Override
        public int getServerPort() {
            return serverPort;
        }

        @Override
        public String getRequestURI() {
            StringBuilder sb = new StringBuilder(contextPath);
            sb.append(getServletPath());
            return sb.toString();
        }

        @Override
        public StringBuffer getRequestURL() {
            StringBuffer sb = new StringBuffer();
            sb.append(scheme).append("://").append(serverName);
            if (includeServerPortInRequestURL) sb.append(":").append(serverPort);
            sb.append(contextPath);
            sb.append(getServletPath());
            if (getPathInfo() != null) sb.append(getPathInfo());
            return sb;
        }

        @Override
        public boolean isSecure() {
            return "https".equalsIgnoreCase(scheme);
        }

    }

    /**
     * Scheme of the LB server - either http or https
     *
     * @param scheme scheme
     */
    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    /**
     * Server name of the LB, e.g. www.myserver.com
     *
     * @param serverName server name
     */
    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    /**
     * Port of the server, in case value is &lt;= 0 port will not be included in the requestURL and port
     * from the original request will be used for getServerPort calls.
     *
     * @param serverPort server port
     */
    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    /**
     * When true serverPort will be used in construction of LB requestURL.
     *
     * @param includeServerPortInRequestURL true to include port
     */
    public void setIncludeServerPortInRequestURL(boolean includeServerPortInRequestURL) {
        this.includeServerPortInRequestURL = includeServerPortInRequestURL;
    }

    /**
     * Context path of the LB, must be starting with slash, e.g. /saml-extension
     *
     * @param contextPath context path
     */
    public void setContextPath(String contextPath) {
        if (contextPath == null || "/".equals(contextPath)) {
            contextPath = "";
        }
        this.contextPath = contextPath;
    }

    /**
     * Verifies that required entities were autowired or set and initializes resolvers used to construct trust engines.
     */
    public void afterPropertiesSet() throws ServletException {

        super.afterPropertiesSet();

        Assert.hasText(scheme, "Scheme must be set");
        Assert.hasText(serverName, "Server name must be set");
        Assert.notNull(contextPath, "Context path must be set");
        if (StringUtils.hasLength(contextPath)) {
            Assert.isTrue(contextPath.startsWith("/"), "Context path must be set and start with a forward slash");
        }

    }

}