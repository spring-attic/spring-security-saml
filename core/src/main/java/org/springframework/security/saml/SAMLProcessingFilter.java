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
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Filter processes arriving SAML messages by delegating to the WebSSOProfile. After the SAMLAuthenticationToken
 * is obtained, authentication providers are asked to authenticate it.
 *
 * @author Vladimir Schäfer
 */
public class SAMLProcessingFilter extends AbstractAuthenticationProcessingFilter {

    protected final static Logger logger = LoggerFactory.getLogger(SAMLProcessingFilter.class);

    protected SAMLProcessor processor;
    protected SAMLContextProvider contextProvider;

    private String filterProcessesUrl;

    /**
     * URL for Web SSO profile responses or unsolicited requests
     */
    public static final String FILTER_URL = "/saml/SSO";

    public SAMLProcessingFilter() {
        this(FILTER_URL);
    }

    protected SAMLProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        setFilterProcessesUrl(defaultFilterProcessesUrl);
    }

    /**
     * In case the login attribute is not present it is presumed that the call is made from the remote IDP
     * and contains a SAML assertion which is processed and authenticated.
     *
     * @param request request
     * @return authentication object in case SAML data was found and valid
     * @throws AuthenticationException authentication failure
     */
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {

            logger.debug("Attempting SAML2 authentication using profile {}", getProfileName());
            SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
            processor.retrieveMessage(context);

            // Override set values
            context.setCommunicationProfileId(getProfileName());
            context.setLocalEntityEndpoint(SAMLUtil.getEndpoint(context.getLocalEntityRoleMetadata().getEndpoints(), context.getInboundSAMLBinding(), context.getInboundMessageTransport()));

            SAMLAuthenticationToken token = new SAMLAuthenticationToken(context);
            return getAuthenticationManager().authenticate(token);

        } catch (SAMLException e) {
            logger.debug("Incoming SAML message is invalid", e);
            throw new AuthenticationServiceException("Incoming SAML message is invalid", e);
        } catch (MetadataProviderException e) {
            logger.debug("Error determining metadata contracts", e);
            throw new AuthenticationServiceException("Error determining metadata contracts", e);
        } catch (MessageDecodingException e) {
            logger.debug("Error decoding incoming SAML message", e);
            throw new AuthenticationServiceException("Error decoding incoming SAML message", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.debug("Incoming SAML message is invalid", e);
            throw new AuthenticationServiceException("Incoming SAML message is invalid", e);
        }

    }

    /**
     * Name of the profile this used for authentication.
     *
     * @return profile name
     */
    protected String getProfileName() {
        return SAMLConstants.SAML2_WEBSSO_PROFILE_URI;
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return SAMLUtil.processFilter(getFilterProcessesUrl(), request);
    }

    /**
     * Use setAuthenticationSuccessHandler method and pass a custom handler instead.
     * <p>
     * Creates a new successHandler and sets default URL for redirect after login. In case user requests a specific
     * page which caused the login process initialization the original page will be reused. Any existing handler
     * will be overwritten.
     *
     * @param url url to use as a default success redirect
     * @see org.springframework.security.saml.SAMLRelayStateSuccessHandler
     * @see org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
     */
    @Deprecated
    public void setDefaultTargetUrl(String url) {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(url);
        setAuthenticationSuccessHandler(handler);
    }


    /**
     * Object capable of parse SAML messages from requests, must be set.
     *
     * @param processor processor
     */
    @Autowired
    public void setSAMLProcessor(SAMLProcessor processor) {
        Assert.notNull(processor, "SAML Processor can't be null");
        this.processor = processor;
    }

    /**
     * Sets entity responsible for populating local entity context data. Must be set.
     *
     * @param contextProvider provider implementation
     */
    @Autowired
    public void setContextProvider(SAMLContextProvider contextProvider) {
        Assert.notNull(contextProvider, "Context provider can't be null");
        this.contextProvider = contextProvider;
    }

    /**
     * Verifies that required entities were autowired or set.
     */
    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
        Assert.notNull(processor, "SAMLProcessor must be set");
        Assert.notNull(contextProvider, "Context provider must be set");
    }

    /**
     * Sets the URL used to determine if this Filter is invoked
     * @param filterProcessesUrl the URL used to determine if this Filter is invoked
     */
    @Override
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
        super.setFilterProcessesUrl(filterProcessesUrl);
    }

    /**
     * Gets the URL used to determine if this Filter is invoked
     * @return the URL used to determine if this Fitler is invoked
     */
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }
}
