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
package org.springframework.security.saml;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.HttpSessionStorage;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter processes arriving SAML Single Logout messages by delegating to the LogoutProfile.
 *
 * @author Vladimir Schäfer
 */
public class SAMLLogoutProcessingFilter extends LogoutFilter {

    /**
     * SAML message processor used to parse SAML message from inbound channel.
     */
    protected SAMLProcessor processor;

    /**
     * Profile to delegate SAML parsing to
     */
    protected SingleLogoutProfile logoutProfile;

    /**
     * Logger of SAML messages.
     */
    protected SAMLLogger samlLogger;

    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(SAMLLogoutProcessingFilter.class);

    /**
     * Default processing URL.
     */
    private static final String DEFAULT_URL = "/saml/SingleLogout";

    /**
     * Constructor defines URL to redirect to after successful logout and handlers.
     *
     * @param logoutSuccessUrl user will be redirected to the url after successful logout
     * @param handlers         handlers to invoke after logout
     */
    public SAMLLogoutProcessingFilter(String logoutSuccessUrl, LogoutHandler... handlers) {
        super(logoutSuccessUrl, handlers);
        this.setFilterProcessesUrl(DEFAULT_URL);
    }

    /**
     * Constructor uses custom implementation for determining URL to redirect after successful logout.
     *
     * @param logoutSuccessHandler custom implementation of the logout logic
     * @param handlers             handlers to invoke after logout
     */
    public SAMLLogoutProcessingFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
        super(logoutSuccessHandler, handlers);
        this.setFilterProcessesUrl(DEFAULT_URL);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        doFilterHttp((HttpServletRequest) req, (HttpServletResponse) res, chain);
    }

    /**
     * Filter loads SAML message from the request object and processes it. In case the message is of LogoutResponse
     * type it is validated and user is redirected to the success page. In case the message is invalid error
     * is logged and user is redirected to the success page anyway.
     * <p/>
     * In case the LogoutRequest message is received it will be verified and local session will be destroyed.
     *
     * @param request  http request
     * @param response http response
     * @param chain    chain
     * @throws IOException      error
     * @throws ServletException error
     */
    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (requiresLogout(request, response)) {

            HttpSessionStorage storage = new HttpSessionStorage(request);
            HttpServletRequestAdapter inTransport = new HttpServletRequestAdapter(request);
            HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
            BasicSAMLMessageContext context = new BasicSAMLMessageContext();
            context.setInboundMessageTransport(inTransport);
            context.setOutboundMessageTransport(outTransport);

            Assert.notNull(logoutProfile, "Logout profile wasn't initialized");
            Assert.notNull(processor, "SAML Processor wasn't initialized");
            logger.debug("Processing SAML2 logout message");

            try {

                processor.retrieveMessage(context);

            } catch (SAMLException e) {
                throw new SAMLRuntimeException("Incoming SAML message is invalid", e);
            } catch (MetadataProviderException e) {
                throw new SAMLRuntimeException("Error determining metadata contracts", e);
            } catch (MessageDecodingException e) {
                throw new SAMLRuntimeException("Error decoding incoming SAML message", e);
            } catch (org.opensaml.xml.security.SecurityException e) {
                throw new SAMLRuntimeException("Incoming SAML message is invalid", e);
            }

            boolean doLogout = true;

            if (context.getInboundSAMLMessage() instanceof LogoutResponse) {

                try {
                    logoutProfile.processLogoutResponse(context, storage);
                    samlLogger.log(SAMLConstants.LOGOUT_RESPONSE, SAMLConstants.SUCCESS, context);
                } catch (Exception e) {
                    samlLogger.log(SAMLConstants.LOGOUT_RESPONSE, SAMLConstants.FAILURE, context);
                    log.warn("Received global logout response is invalid", e);
                }

            } else if (context.getInboundMessage() instanceof LogoutRequest) {

                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                SAMLCredential credential = null;
                if (auth != null) {
                    credential = (SAMLCredential) auth.getCredentials();
                }

                try {
                    // Process request and send response to the sender in case the request is valid
                    doLogout = logoutProfile.processLogoutRequest(context, credential);
                    samlLogger.log(SAMLConstants.LOGOUT_REQUEST, SAMLConstants.SUCCESS, context);
                } catch (Exception e) {
                    samlLogger.log(SAMLConstants.LOGOUT_REQUEST, SAMLConstants.FAILURE, context);
                    log.warn("Received global logout request is invalid", e);
                }

            }

            if (doLogout) {
                super.doFilter(request, response, chain);
            }

        } else {
            chain.doFilter(request, response);
        }

    }

    @Required
    public void setSAMLProcessor(SAMLProcessor processor) {
        this.processor = processor;
    }

    @Required
    public void setLogoutProfile(SingleLogoutProfile logoutProfile) {
        this.logoutProfile = logoutProfile;
    }

    @Override
    public String getFilterProcessesUrl() {
        return super.getFilterProcessesUrl();
    }

    @Required
    public void setSamlLogger(SAMLLogger samlLogger) {
        this.samlLogger = samlLogger;
    }    

}