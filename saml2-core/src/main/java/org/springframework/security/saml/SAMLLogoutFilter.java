/*
 * Copyright 2009 Vladimir Schäfer
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
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.storage.HttpSessionStorage;
import org.springframework.security.saml.util.SAMLUtil;
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
 * Logout filter leveraging SAML 2.0 Single Logout profile. Upon invocation of the filter URL it is
 * determined whether global (termination of all participating sessions) or local (termination of only
 * session running within Spring Security) logout is requested based on request attribute.
 * <p/>
 * In case global logout is in question a LogoutRequest is sent to the IDP.
 *
 * @author Vladimir Schäfer
 */
public class SAMLLogoutFilter extends LogoutFilter {

    /**
     * Default name of path suffix which will invoke this filter.
     */
    private static final String DEFAULT_FILTER_URL = "/saml/logout";

    /**
     * Implementation of SAML logout profile.
     */
    @Autowired
    private SingleLogoutProfile profile;

    /**
     * Logger of SAML messages.
     */
    @Autowired
    protected SAMLLogger samlLogger;

    /**
     * Name of parameter of HttpRequest indicating whether this call should perform only local logout.
     * In case the value is true no global logout will be invoked.
     */
    protected static final String LOGOUT_PARAMETER = "local";

    /**
     * Handlers to be invoked during logout.
     */
    private LogoutHandler[] globalHandlers;

    /**
     * Default constructor.
     *
     * @param successUrl     url to use after logout in case of local logout
     * @param localHandler   handlers to be invoked when local logout is selected
     * @param globalHandlers handlers to be invoked when global logout is selected
     */
    public SAMLLogoutFilter(String successUrl, LogoutHandler[] localHandler, LogoutHandler[] globalHandlers) {
        super(successUrl, localHandler);
        this.globalHandlers = globalHandlers;
        this.setFilterProcessesUrl(DEFAULT_FILTER_URL);
    }

    /**
     * Default constructor.
     *
     * @param logoutSuccessHandler handler to invoke upon successful logout
     * @param localHandler         handlers to be invoked when local logout is selected
     * @param globalHandlers       handlers to be invoked when global logout is selected
     */
    public SAMLLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler[] localHandler, LogoutHandler[] globalHandlers) {
        super(logoutSuccessHandler, localHandler);
        this.globalHandlers = globalHandlers;
        this.setFilterProcessesUrl(DEFAULT_FILTER_URL);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        doFilterHttp((HttpServletRequest) req, (HttpServletResponse) res, chain);
    }

    /**
     * In case request parameter of name "local" is set to true or there is no authenticated user
     * only local logout will be performed and user will be redirected to the success page.
     * Otherwise global logout procedure is initialized.
     */
    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        Assert.notNull(profile, "LogoutProfile wasn't initialized in SAMLLogoutEntry object");

        if (requiresLogout(request, response)) {

            BasicSAMLMessageContext context = getContext(request, response);

            try {

                Authentication auth = SecurityContextHolder.getContext().getAuthentication();

                if (auth != null && isGlobalLogout(request, auth)) {

                    Assert.isInstanceOf(SAMLCredential.class, auth.getCredentials(), "Authentication object doesn't contain SAML credential");
                    SAMLCredential credential = (SAMLCredential) auth.getCredentials();
                    HttpSessionStorage storage = new HttpSessionStorage(request);
                    profile.sendLogoutRequest(context, credential, storage);
                    samlLogger.log(SAMLConstants.LOGOUT_REQUEST, SAMLConstants.SUCCESS, context);

                    for (LogoutHandler handler : globalHandlers) {
                        handler.logout(request, response, auth);
                    }

                } else {

                    super.doFilter(request, response, chain);
                }

            } catch (SAMLException e1) {
                throw new ServletException("Error initializing global logout", e1);
            } catch (MetadataProviderException e1) {
                throw new ServletException("Error processing metadata", e1);
            } catch (MessageEncodingException e1) {
                throw new ServletException("Error encoding outgoing message", e1);
            }

        } else {

            chain.doFilter(request, response);
        }

    }

    /**
     * Method populates the SAML context. Fields inbound and outbound transport must be filled. Also
     * localEntityId and localEntityRole may be selected.
     *
     * @param request  request
     * @param response response
     * @return saml context
     * @see org.springframework.security.saml.util.SAMLUtil#getContext(HttpServletRequest, HttpServletResponse)
     * @see org.springframework.security.saml.util.SAMLUtil#populateLocalEntity(BasicSAMLMessageContext, String)
     */
    protected BasicSAMLMessageContext getContext(HttpServletRequest request, HttpServletResponse response) {
        BasicSAMLMessageContext context = SAMLUtil.getContext(request, response);
        SAMLUtil.populateLocalEntity(context, request.getContextPath());
        return context;
    }

    /**
     * The filter will be used in case the URL of the request contains the DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        return SAMLUtil.processFilter(getFilterProcessesUrl(), request);
    }

    /**
     * Performs global logout in case current user logged in using SAML and user hasn't selected local logout only
     *
     * @param request request
     * @param auth    currently logged in user
     * @return true if single logout with IDP is required
     */
    protected boolean isGlobalLogout(HttpServletRequest request, Authentication auth) {
        String login = request.getParameter(LOGOUT_PARAMETER);
        return (login == null || !"true".equals(login.toLowerCase().trim())) && (auth.getCredentials() instanceof SAMLCredential);
    }

    public void setSamlLogger(SAMLLogger samlLogger) {
        this.samlLogger = samlLogger;
    }

    public void setProfile(SingleLogoutProfile profile) {
        this.profile = profile;
    }

}