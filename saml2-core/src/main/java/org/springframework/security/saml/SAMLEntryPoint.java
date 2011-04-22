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
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import java.util.List;

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

    protected final static Logger logger = LoggerFactory.getLogger(SAMLEntryPoint.class);

    /**
     * In case this property is set to not null value the user will be redirected to this URL for selection
     * of IDP to use for login. In case it is null user will be redirected to the default IDP.
     */
    protected String idpSelectionPath;
    protected String idpDiscoveryURL;
    protected WebSSOProfileOptions defaultOptions;
    protected WebSSOProfile webSSOprofile;
    protected WebSSOProfile webSSOprofileECP;
    protected MetadataManager metadata;
    protected SAMLLogger samlLogger;
    protected SAMLContextProvider contextProvider;

    /**
     * Default name of path suffix which will invoke this filter.
     */
    private static final String DEFAULT_FILTER_URL = "/saml/login";

    /**
     * Name of parameter of HttpRequest telling entry point that the login should use specified idp.
     */
    public static final String IDP_PARAMETER = "idp";

    /**
     * Name of parameter of HttpRequest indicating whether this call should skip IDP selection
     * and send immediately SAML request. Calls from IDP selection must always set this attribute
     * to true.
     */
    public static final String LOGIN_PARAMETER = "login";

    /**
     * Parameter is used to indicate response from IDP discovery service. When present IDP discovery is not invoked
     * again.
     */
    public static final String DISCOVERY_RESPONSE_PARAMETER = "disco";

    /**
     * User configured path which overrides the default value.
     */
    protected String filterProcessesUrl = DEFAULT_FILTER_URL;

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilterHttp((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    /**
     * In case the DEFAULT_FILTER_URL is invoked directly, the filter will get called and initialize the
     * login sequence.
     *
     * @param request  request
     * @param response response
     * @param chain    filter chain
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
        return SAMLUtil.processFilter(filterProcessesUrl, request);
    }

    /**
     * Method should commence mechanism used to ultimately authenticate user using WebSSO Profile. First task of the mechanism
     * is to determine which IDP to use. Options are let the user agent determine IDP for us (ECP profile), use IDP discovery
     * to determine IDP, let user select which IDP to use or use the default IDP. The following logic is used to determine our case:
     * <p/>
     * <ul>
     * <li>In case request supports Enhanced Client or Proxy as per SAML specification and ECP is supported authentication is initialized using ECP.</li>
     * <li>In case IDP Discovery URL is configured and the current request doesn't already contain IDP information or forces login or is a discovery profile response then IDP Discovery is initialized.</li>
     * <li>In case IDP Selection Path is configured and the current request doesn't already contain IDP information or force login then user is forwarded for IDP selection using RequestDispatcher.</li>
     * <li>In case login is forced, IDP is already specified or no discovery or idpSelection is configured WebSSO is initialized.</li>
     * </ul>
     * <p/>
     * IDPDiscovery URL is configured using idpDiscoveryURL property. Setting property "login" of the HTTP request to "true" will
     * force login which means that all IDP discovery mechanisms will be skipped and either default IDP or IDP specified in the request will be used.
     *
     * @param request  request
     * @param response response
     * @param e        exception causing this entry point to be invoked
     * @throws IOException      error sending response
     * @throws ServletException error initializing SAML protocol
     */
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {

        try {

            boolean ecpRequest = isECPRequest(request);
            boolean loginRequest = isLoginRequest(request);
            boolean discoResponse = isDiscoResponse(request);

            if (!loginRequest && ecpRequest && webSSOprofileECP != null) {

                // Automatic IDP discovery using ECP
                initializeECPSSO(request, response, e);

            } else if (!loginRequest && !discoResponse && idpDiscoveryURL != null) {

                // IDP Discovery profile
                initializeIDPDisco(request, response);

            } else if (!loginRequest && idpSelectionPath != null) {

                // User selection of IDP
                initializeSelection(request, response);

            } else {

                initializeSSO(request, response, e);

            }

        } catch (SAMLException e1) {
            throw new ServletException("Error sending assertion", e1);
        } catch (MetadataProviderException e1) {
            throw new ServletException("Error processing metadata", e1);
        } catch (MessageEncodingException e1) {
            throw new ServletException("Error encoding outgoing message", e1);
        }

    }

    protected void initializeECPSSO(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws MetadataProviderException, ServletException, SAMLException, MessageEncodingException {

        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        SAMLMessageStorage storage = new HttpSessionStorage(request);
        WebSSOProfileOptions options = getProfileOptions(request, response, context, e);

        logger.debug("Processing SSO using ECP profile");
        webSSOprofileECP.sendAuthenticationRequest(context, options, storage);
        samlLogger.log(SAMLConstants.AUTH_N_REQUEST, SAMLConstants.SUCCESS, context, e);

    }

    protected void initializeSSO(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws MetadataProviderException, ServletException, SAMLException, MessageEncodingException {

        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        SAMLMessageStorage storage = new HttpSessionStorage(request);
        WebSSOProfileOptions options = getProfileOptions(request, response, context, e);

        logger.debug("Processing SSO request");
        webSSOprofile.sendAuthenticationRequest(context, options, storage);
        samlLogger.log(SAMLConstants.AUTH_N_REQUEST, SAMLConstants.SUCCESS, context, e);

    }

    /**
     * Method is expected to initialize IDP selection in the client's browser by including appropriate source. By default
     * page located at idpSelectionPath is included.
     *
     * @param request  request
     * @param response response
     * @throws ServletException error
     * @throws IOException      io error
     */
    protected void initializeSelection(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        logger.debug("Initializing IDP selection");
        request.getRequestDispatcher(idpSelectionPath).forward(request, response);

    }

    /**
     * Method initializes IDP Discovery Profile as defined in http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf
     * It is presumed that metadata of the local Service Provider contains discovery return address.
     *
     * @param request  request
     * @param response response
     * @throws ServletException          error
     * @throws IOException               io error
     * @throws MetadataProviderException in case metadata of the local entity can't be populated
     */
    protected void initializeIDPDisco(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, MetadataProviderException {

        logger.debug("Initializing IDP discovery profile");
        SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
        URLBuilder urlBuilder = new URLBuilder(idpDiscoveryURL);
        List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
        queryParams.add(new Pair<String, String>("entityID", context.getLocalEntityId()));
        queryParams.add(new Pair<String, String>("returnIDParam", IDP_PARAMETER));
        response.sendRedirect(urlBuilder.buildURL());

    }

    /**
     * Analyzes the request headers in order to determine if it comes from an ECP-enabled
     * client and based on this decides whether ECP profile will be used. Subclasses can override
     * the method to control when is the ECP invoked.
     *
     * @param request request to analyze
     * @return whether the request comes from an ECP-enabled client or not
     */
    protected boolean isECPRequest(HttpServletRequest request) {

        String acceptHeader = request.getHeader("Accept");
        String paosHeader = request.getHeader(SAMLConstants.PAOS_HTTP_HEADER);
        return acceptHeader != null && paosHeader != null
                && acceptHeader.contains(SAMLConstants.PAOS_HTTP_ACCEPT_HEADER)
                && paosHeader.contains(org.opensaml.common.xml.SAMLConstants.PAOS_NS)
                && paosHeader.contains(org.opensaml.common.xml.SAMLConstants.SAML20ECP_NS);

    }

    /**
     * Method is supposed to populate preferences used to construct the SAML message. Method can be overridden to provide
     * logic appropriate for given application. In case defaultOptions object was set it will be used as basis for construction
     * and request specific values will be update (idp field).
     *
     * @param request   request
     * @param response  response
     * @param context   containing local entity
     * @param exception exception causing invocation of this entry point (can be null)
     * @return populated webSSOprofile
     * @throws MetadataProviderException in case metadata loading fails
     * @throws ServletException          in case any other error occurs
     */
    protected WebSSOProfileOptions getProfileOptions(HttpServletRequest request, HttpServletResponse response, SAMLMessageContext context, AuthenticationException exception) throws MetadataProviderException, ServletException {

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
     * Method determines whether request should directly proceed with SSO procedure. Login is initialized when either
     * property login is set to true or when property idp is specified.
     *
     * @param request request
     * @return true if this HttpRequest should be directly forwarded to the IDP without selection of IDP.
     */
    protected boolean isLoginRequest(HttpServletRequest request) {
        String login = request.getParameter(LOGIN_PARAMETER);
        String idp = request.getParameter(IDP_PARAMETER);
        return (login != null && login.toLowerCase().trim().equals("true")) || idp != null;
    }

    /**
     * True value indicates that request is a response from the discovery profile. We use the value to
     * prevent repeated invocation of the discovery service upon failure.
     *
     * @param request request
     * @return true if this HttpRequest is a response from IDP discovery profile.
     */
    protected boolean isDiscoResponse(HttpServletRequest request) {
        String disco = request.getParameter(DISCOVERY_RESPONSE_PARAMETER);
        return disco != null && disco.toLowerCase().trim().equals("true");
    }

    /**
     * Loads the IDP_PARAMETER from the request and if it is not null verifies whether IDP with this value is valid
     * IDP in our circle of trust. Processing fails when IDP is not valid.
     * <p/>
     * If request parameter is null the default IDP is returned.
     *
     * @param request request
     * @return null if idp is not set or invalid, name of IDP otherwise
     * @throws MetadataProviderException in case provided IDP value is invalid
     */
    protected String getIDP(HttpServletRequest request) throws MetadataProviderException {
        String idp = request.getParameter(IDP_PARAMETER);
        if (idp != null) {
            if (metadata.isIDPValid(idp)) {
                return idp;
            } else {
                throw new MetadataProviderException("Given IDP is invalid: " + idp);
            }
        } else {
            return metadata.getDefaultIDP();
        }
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

    /**
     * Sets suffix processed by this entry point. Cannot be null. By default value /saml/login is used.
     *
     * @param filterSuffix suffix
     */
    public void setFilterProcessesUrl(String filterSuffix) {
        Assert.notNull(filterSuffix, "Suffix cannot be null");
        this.filterProcessesUrl = filterSuffix;
    }

    /**
     * URL this filter expects requests at.
     * @return url
     */
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
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

    /**
     * Sets path where request dispatcher will send user for IDP selection. In case it is null the default
     * server will always be used.
     *
     * @param idpSelectionPath selection path
     */
    public void setIdpSelectionPath(String idpSelectionPath) {
        this.idpSelectionPath = idpSelectionPath;
    }

    /**
     * Profile for consumption of processed messages, cannot be null, must be set.
     *
     * @param webSSOprofile profile
     */
    @Autowired
    @Qualifier("webSSOprofile")
    public void setWebSSOprofile(WebSSOProfile webSSOprofile) {
        Assert.notNull(webSSOprofile, "WebSSOPRofile can't be null");
        this.webSSOprofile = webSSOprofile;
    }

    public WebSSOProfile getWebSSOprofileECP() {
        return webSSOprofileECP;
    }

    @Autowired(required = false)
    @Qualifier("ecpprofile")
    public void setWebSSOprofileECP(WebSSOProfile webSSOprofileECP) {
        this.webSSOprofileECP = webSSOprofileECP;
    }

    /**
     * Logger for SAML events, cannot be null, must be set.
     *
     * @param samlLogger logger
     */
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

    /**
     * Metadata manager, cannot be null, must be set.
     *
     * @param metadata manager
     */
    @Autowired
    public void setMetadata(MetadataManager metadata) {
        Assert.notNull(metadata, "MetadataManager can't be null");
        this.metadata = metadata;
    }

    /**
     * Verifies that required entities were autowired or set.
     *
     * @throws ServletException
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(webSSOprofile, "WebSSO profile must be set");
        Assert.notNull(metadata, "Metadata must be set");
        Assert.notNull(samlLogger, "Logger must be set");
        Assert.notNull(contextProvider, "Context provider must be set");
    }

}
