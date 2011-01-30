/* Copyright 2009-2011 Vladimir Schaefer
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
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.HttpSessionStorage;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Class initializes SAML WebSSO profile from the SP side. AuthnRequest is sent to the default IDP
 * with default binding.
 * <p/>
 * There are two ways the entry point can get invoked. Either user accesses a URL configured to require
 * some degree of authentication and throws AuthenticationException which is handled and invokes the entry point.
 * <p/>
 * The other way is direct invocation of the entry point by accessing the DEFAULT_FILTER_URL. In this way user
 * can be forwarded to IDP after clicking for example login button.
 *
 * @author Vladimir Schaefer
 */
public class SAMLEntryPoint extends GenericFilterBean implements AuthenticationEntryPoint {

    /**
     * In case this property is set to not null value the user will be redirected to this URL for selection
     * of IDP to use for login. In case it is null user will be redirected to the default IDP.
     */
    private String idpSelectionPath;

    private WebSSOProfileOptions defaultOptions;

    private WebSSOProfile webSSOprofile;
    private MetadataManager metadata;
    private SAMLLogger samlLogger;
    private SAMLContextProvider contextProvider;

    /**
     * Default name of path suffix which will invoke this filter.
     */
    private static final String DEFAULT_FILTER_URL = "/saml/login";

    /**
     * Name of parameter of HttpRequest telling entry point that the login should use specified idp.
     */
    protected static final String IDP_PARAMETER = "idp";

    /**
     * Name of parameter of HttpRequest indicating whether this call should skip IDP selection
     * and send immediately SAML request. Calls from IDP selection must always set this attribute
     * to true.
     */
    protected static final String LOGIN_PARAMETER = "login";

    /**
     * User configured path which overrides the default value.
     */
    private String filterProcessesUrl;

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilterHttp((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    /**
     * In case the DEFAULT_FILTER_URL is invoked directly, the filter will get called and initialize the
     * login sequence.
     */
    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (processFilter(request)) {
            commence(request, response, null);
        } else {
            chain.doFilter(request, response);
        }
    }

    /**
     * The filter will be used in case the URL of the request contains the DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        return SAMLUtil.processFilter(getFilterProcessesUrl(), request);
    }    

    /**
     * Sends AuthNRequest to the default IDP using any binding supported by both SP and IDP.
     *
     * @param request  request
     * @param response response
     * @param e        exception causing this entry point to be invoked
     * @throws IOException      error sending response
     * @throws ServletException error initializing SAML protocol
     */
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {

        try {

            if (idpSelectionPath != null && !isLoginRequest(request)) {
                request.getRequestDispatcher(idpSelectionPath).include(request, response);
            } else {
                SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
                SAMLMessageStorage storage = new HttpSessionStorage(request);
                WebSSOProfileOptions options = getProfileOptions(request, response, e);
                webSSOprofile.sendAuthenticationRequest(context, options, storage);
                samlLogger.log(SAMLConstants.AUTH_N_REQUEST, SAMLConstants.SUCCESS, context, e);
            }

        } catch (SAMLException e1) {
            throw new ServletException("Error sending assertion", e1);
        } catch (MetadataProviderException e1) {
            throw new ServletException("Error processing metadata", e1);
        } catch (MessageEncodingException e1) {
            throw new ServletException("Error encoding outgoing message", e1);
        }

    }

    /**
     * Method is supposed to populate preferences used to construct the SAML message. Method can be overridden to provide
     * logic appropriate for given application. In case defaultOptions object was set it will be used as basis for construction
     * and request specific values will be update (idp field).
     *
     * @param request   request
     * @param response  response
     * @param exception exception causing invocation of this entry point (can be null)
     * @return populated webSSOprofile
     * @throws MetadataProviderException in case metadata loading fails
     * @throws ServletException          in case any other error occurs
     */
    protected WebSSOProfileOptions getProfileOptions(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws MetadataProviderException, ServletException {

        WebSSOProfileOptions ssoProfileOptions;
        if (defaultOptions != null) {
            ssoProfileOptions = defaultOptions.clone();
        } else {
            ssoProfileOptions = new WebSSOProfileOptions();
        }
        ssoProfileOptions.setIdp(getIDP(request));

        return ssoProfileOptions;

    }

    /**
     * Sets object which determines default values to be used as basis for construction during getProfileOptions call.
     *
     * @param defaultOptions default object to use for options construction
     */
    public void setDefaultProfileOptions(WebSSOProfileOptions defaultOptions) {
        if (defaultOptions != null) {
            this.defaultOptions = defaultOptions.clone();
        } else {
            this.defaultOptions = null;
        }
    }

    /**
     * @param request request
     * @return true if this HttpRequest should be directly forwarded to the IDP without selection of IDP.
     */
    private boolean isLoginRequest(HttpServletRequest request) {
        String login = request.getParameter(LOGIN_PARAMETER);
        return login != null && login.toLowerCase().trim().equals("true");
    }

    /**
     * Loads the IDP_PARAMETER from the request and if it is not null verifies whether IDP with this value is valid
     * IDP in our circle of trust. If it is null or the IDP is not configured then the default IDP is returned.
     *
     * @param request request
     * @return null if idp is not set or invalid, name of IDP otherwise
     * @throws MetadataProviderException in case no IDP is configured
     */
    protected String getIDP(HttpServletRequest request) throws MetadataProviderException {
        String s = request.getParameter(IDP_PARAMETER);
        if (s != null) {
            for (String idp : metadata.getIDPEntityNames()) {
                if (idp.equals(s)) {
                    return idp;
                }
            }
            throw new MetadataProviderException("Given IDP is invalid: " + s);
        }
        return metadata.getDefaultIDP();
    }

    /**
     * Null if not set otherwise path used for requestDispatcher where user will be redirected for IDP
     * selection.
     *
     * @return null or path
     */
    public String getIdpSelectionPath() {
        return idpSelectionPath;
    }

    public String getFilterProcessesUrl() {
        if (filterProcessesUrl == null) {
            return DEFAULT_FILTER_URL;
        } else {
            return filterProcessesUrl;
        }
    }

    public void setFilterProcessesUrl(String filterSuffix) {
        this.filterProcessesUrl = filterSuffix;
    }

    /**
     * Use getFilterProcessesUrl instead.
     *
     * @return suffix
     */
    @Deprecated
    public String getFilterSuffix() {
        return getFilterProcessesUrl();
    }

    /**
     * Use setFilterProcessesUrl instead.
     *
     * @param filterSuffix filter suffix
     */
    @Deprecated
    public void setFilterSuffix(String filterSuffix) {
        setFilterProcessesUrl(filterSuffix);
    }

    public WebSSOProfile getWebSSOprofile() {
        return webSSOprofile;
    }

    /**
     * Sets path where request dispatcher will send user for IDP selection. In case it is null the default
     * server will always be used.
     *
     * @param idpSelectionPath selection path
     */
    public void setIdpSelectionPath(String idpSelectionPath) {
        this.idpSelectionPath = idpSelectionPath;
    }

    @Autowired
    public void setWebSSOprofile(WebSSOProfile webSSOprofile) {
        Assert.notNull(webSSOprofile, "WebSSOPRofile can't be null");
        this.webSSOprofile = webSSOprofile;
    }

    @Autowired
    public void setSamlLogger(SAMLLogger samlLogger) {
        Assert.notNull(samlLogger, "SAML Logger can't be null");
        this.samlLogger = samlLogger;
    }

    /**
     * Sets entity responsible for populating local entity context data.
     *
     * @param contextProvider provider implementation
     */
    @Autowired
    public void setContextProvider(SAMLContextProvider contextProvider) {
        Assert.notNull(contextProvider, "Context provider can't be null");
        this.contextProvider = contextProvider;
    }

    @Autowired
    public void setMetadata(MetadataManager metadata) {
        Assert.notNull(metadata, "MetadataManager can't be null");
        this.metadata = metadata;
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(webSSOprofile, "WebSSO profile must be set");
        Assert.notNull(metadata, "Metadata must be set");
        Assert.notNull(samlLogger, "Logger must be set");
        Assert.notNull(contextProvider, "Context provider must be set");
    }

}
