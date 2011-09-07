/* Copyright 2011 Vladimir Schaefer
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

import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.samlext.idpdisco.DiscoveryResponse;
import org.opensaml.util.URLBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.FilterInvocation;
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
 * Filter implements Identity Provider Discovery Service as defined in initializes IDP Discovery Profile as defined in
 * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf.
 *
 * @author Vladimir Schaefer
 */
public class SAMLDiscovery extends GenericFilterBean {

    protected final static Logger logger = LoggerFactory.getLogger(SAMLDiscovery.class);

    /**
     * Used to store return URL in the forwarded request object.
     */
    public static final String RETURN_URL = "idpDiscoReturnURL";

    /**
     * Used to store return parameter in the forwarded request object.
     */
    public static final String RETURN_PARAM = "idpDiscoReturnParam";

    /**
     * Unique identifier of the party performing the request. Part of IDP Disco specification.
     */
    public static final String ENTITY_ID_PARAM = "entityID";

    /**
     * URL used by the discovery service to send the response. Value is verified against metadata of the requesting
     * entity. URL can contain additional query part, but mustn't include the same attribute as specified in returnIdParam.
     * Part of IDP Disco specification.
     */
    public static final String RETURN_URL_PARAM = "return";

    /**
     * Request parameter specifying which response attribute to use for conveying the determined IDP name.
     * Uses "entityID" when empty. Part of IDP Disco specification.
     */
    public static final String RETURN_ID_PARAM = "returnIDParam";

    /**
     * Policy to use in order to determine IDP. Only the default IDP_DISCO_PROTOCOL_SINGLE is supported and is
     * also used when policy request attribute is unspecified. Part of IDP Disco specification.
     */
    public static final String POLICY_PARAM = "policy";

    /**
     * Request parameter indicating whether discovery service can interact with the user agent. Allowed
     * values are "true" or "false" Set to "false" when unspecified. Part of IDP Disco specification.
     */
    public static final String PASSIVE_PARAM = "isPassive";

    /**
     * In case this property is set to not null value the user will be redirected to this URL for selection
     * of IDP to use for login. In case it is null user will be redirected to the default IDP.
     */
    protected String idpSelectionPath;

    /**
     * Metadata manager used to look up entity IDs and discovery URLs.
     */
    protected MetadataManager metadata;

    /**
     * Default name of path suffix which will invoke this filter.
     */
    public static final String FILTER_URL = "/saml/discovery";

    /**
     * Default profile of the discovery service.
     */
    public static final String IDP_DISCO_PROTOCOL_SINGLE = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single";

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        processDiscoveryRequest(fi.getRequest(), fi.getResponse());

    }

    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        return SAMLUtil.processFilter(FILTER_URL, request);
    }

    /**
     * Method processes IDP Discovery request, validates it for conformity and either sends a passive response with
     * default IDP (when isPassive mode is requested) or forwards browser to the IDP selection. By default the
     * page located at idpSelectionPath is included.
     *
     * @param request  request
     * @param response response
     * @throws javax.servlet.ServletException error
     * @throws java.io.IOException            io error
     */
    protected void processDiscoveryRequest(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

        logger.debug("Processing IDP Discovery Service request");

        // Requesting entity, MUST be present and valid, IDPDisco, 239
        String entityId = request.getParameter(ENTITY_ID_PARAM);

        if (entityId == null) {
            logger.debug("Received IDP Discovery request without entityId");
            throw new SAMLRuntimeException("Entity ID parameter must be specified");
        }

        // Load entity metadata (IDP Disco, 318)
        RoleDescriptor roleDescriptor;
        ExtendedMetadata extendedMetadata;

        try {
            roleDescriptor = metadata.getRole(entityId, SPSSODescriptor.DEFAULT_ELEMENT_NAME, org.opensaml.common.xml.SAMLConstants.SAML20P_NS);
            extendedMetadata = metadata.getExtendedMetadata(entityId);
        } catch (MetadataProviderException e) {
            logger.debug("Error loading metadata", e);
            throw new SAMLRuntimeException("Error loading metadata");
        }

        if (roleDescriptor == null) {
            logger.debug("Received IDP Discovery request with unrecognized entityId {}", entityId);
            throw new SAMLRuntimeException("Entity ID in the request is not valid");
        }

        // URL to return the selected IDP to, use default when not present
        String returnURL = request.getParameter(RETURN_URL_PARAM);
        if (returnURL == null) {
            returnURL = getDefaultReturnURL(roleDescriptor, extendedMetadata);
        } else if (!isResponseURLValid(returnURL, roleDescriptor, extendedMetadata)) {
            logger.debug("Return URL {} designated in IDP Discovery request for entity {} is not valid", returnURL, entityId);
            throw new SAMLRuntimeException("Return URL designated in IDP Discovery request for entity is not valid");
        }

        // Policy to be used, MAY be present, only default "single" policy is supported
        String policy = request.getParameter(POLICY_PARAM);
        if (policy != null && !policy.equals(IDP_DISCO_PROTOCOL_SINGLE)) {
            logger.debug("Received IDP Discovery with unsupported policy {}", policy);
            throw new SAMLRuntimeException("Unsupported IDP discovery profile was requested");
        }

        // Return ID parameter name
        String returnParam = request.getParameter(RETURN_ID_PARAM);
        if (returnParam == null) {
            returnParam = "entityID";
        }

        String isPassive = request.getParameter(PASSIVE_PARAM);
        if (isPassive != null && "true".equals(isPassive)) {

            // Send a passive response
            String passiveIDP = getPassiveIDP(request);
            sendPassiveResponse(request, response, returnURL, returnParam, passiveIDP);

        } else {

            // Initialize IDP selection
            sendIDPSelection(request, response, returnURL, returnParam);

        }

    }

    /**
     * Creates a URL to be used for returning of the selected IDP and sends a redirect.
     *
     * @param request     request object
     * @param response    response object
     * @param responseURL base for the return URL
     * @param returnParam parameter name to send the IDP entityId in
     * @param entityID    entity ID to send or null for fail state
     * @throws IOException      in case redirect sending fails
     * @throws ServletException in case redirect sending fails
     */
    protected void sendPassiveResponse(HttpServletRequest request, HttpServletResponse response, String responseURL, String returnParam, String entityID) throws IOException, ServletException {

        if (entityID != null) {
            URLBuilder urlBuilder = new URLBuilder(responseURL);
            List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
            queryParams.add(new Pair<String, String>(returnParam, entityID));
            responseURL = urlBuilder.toString();
        }

        logger.debug("Responding to a passive IDP Discovery request with URL {}", responseURL);
        response.sendRedirect(responseURL);

    }

    /**
     * Forward the request to a page which renders IDP selection page for the user. The URL for redirect
     * and param for IDP selection are included as request attributes under keys with constant names
     * RETURN_URL and RETURN_PARAM.
     *
     * @param request     request object
     * @param response    response object
     * @param responseURL base for the return URL
     * @param returnParam parameter name to send the IDP entityId in
     * @throws IOException      in case forwarding to the selection page fails
     * @throws ServletException in case forwarding to the selection page fails
     */
    protected void sendIDPSelection(HttpServletRequest request, HttpServletResponse response, String responseURL, String returnParam) throws IOException, ServletException {

        // Store the value
        request.setAttribute(RETURN_URL, responseURL);
        request.setAttribute(RETURN_PARAM, returnParam);

        String path = getIdpSelectionPath();
        logger.debug("Initializing IDP Discovery selection page at {} with return url {}", path, responseURL);
        request.getRequestDispatcher(path).forward(request, response);

    }

    /**
     * Provides default return URL based on metadata in case none was supplied in the request. URL is automatically generated
     * for local entities which do not contain discovery URL in metadata.
     *
     * @param descriptor       descriptor of the requesting entity
     * @param extendedMetadata extended metadata of the requesting entity
     * @return URL to return the selected IDP to
     * @throws SAMLRuntimeException in case entity is remote and doesn't contain URL in metadata
     */
    protected String getDefaultReturnURL(RoleDescriptor descriptor, ExtendedMetadata extendedMetadata) {

        // Load from metadata extensions
        if (descriptor.getExtensions() != null) {
            List<XMLObject> discoveryResponseElements = descriptor.getExtensions().getUnknownXMLObjects(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
            for (XMLObject element : discoveryResponseElements) {
                DiscoveryResponse response = (DiscoveryResponse) element;
                if (response.getBinding().equals(DiscoveryResponse.IDP_DISCO_NS)) {
                    logger.debug("Using IDP Discovery response URL from metadata {}", response.getLocation());
                    return response.getLocation();
                }
            }
        }

        // Generation for local entities at known URL
        if (extendedMetadata.isLocal()) {
            StringBuilder sb = new StringBuilder(50);
            sb.append(getServletContext().getContextPath());
            sb.append(SAMLEntryPoint.FILTER_URL + "/alias/");
            sb.append(extendedMetadata.getAlias());
            sb.append("?" + SAMLEntryPoint.DISCOVERY_RESPONSE_PARAMETER + "=true");
            String responseURL = sb.toString();
            logger.debug("Using IDP Discovery response URL calculated for local entity {}", responseURL);
            return responseURL;
        }

        throw new SAMLRuntimeException("Can't determine IDP Discovery return URL for entity " + descriptor.getID());

    }

    /**
     * Verifies whether return URL supplied in the request is valid. By default it is verified that the host part of the
     * supplied URL is the same as the host part of the default response location in metadata (IDP Disco, 320)
     *
     * @param returnURL        URL from the request
     * @param roleDescriptor   descriptor of the requesting entity
     * @param extendedMetadata extended metadata of the requesting entity
     * @return true if the request is valid, false otherwise
     */
    protected boolean isResponseURLValid(String returnURL, RoleDescriptor roleDescriptor, ExtendedMetadata extendedMetadata) {

        URLBuilder foundURL = new URLBuilder(returnURL);
        URLBuilder defaultURL = new URLBuilder(getDefaultReturnURL(roleDescriptor, extendedMetadata));

        if (!defaultURL.getHost().equals(foundURL.getHost())) {
            return false;
        }

        return true;

    }

    /**
     * Returns IDP to be used in passive mode. By default the default IDP designated so in metadata is used.
     *
     * @param request IDP discovery request
     * @return IDP configured as default or null when no such exists
     */
    protected String getPassiveIDP(HttpServletRequest request) {
        try {
            return metadata.getDefaultIDP();
        } catch (MetadataProviderException e) {
            return null;
        }
    }

    /**
     * Path used to forward request in order to enable target IDP selecton/
     *
     * @return path for forward
     */
    public String getIdpSelectionPath() {
        return idpSelectionPath;
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
     * @throws javax.servlet.ServletException
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(metadata, "Metadata must be set");
    }

}