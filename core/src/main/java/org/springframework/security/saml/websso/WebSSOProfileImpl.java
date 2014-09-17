/* Copyright 2009 Vladimir Schafer
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
package org.springframework.security.saml.websso;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.SAMLMessageStorage;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Class implements WebSSO profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect
 * bindings are supported.
 *
 * @author Vladimir Schafer
 */
public class WebSSOProfileImpl extends AbstractProfileBase implements WebSSOProfile {

    public WebSSOProfileImpl() {
    }

    public WebSSOProfileImpl(SAMLProcessor processor, MetadataManager manager) {
        super(processor, manager);
    }

    @Override
    public String getProfileIdentifier() {
        return SAMLConstants.SAML2_WEBSSO_PROFILE_URI;
    }

    /**
     * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the default binding.
     * Default IDP is used to send the request.
     *
     *
     * @param options        values specified by caller to customize format of sent request
     * @throws SAMLException             error initializing SSO
     * @throws SAMLRuntimeException in case context doesn't contain required entities or contains invalid data
     * @throws MetadataProviderException error retrieving needed metadata
     * @throws MessageEncodingException  error forming SAML message
     */
    public void sendAuthenticationRequest(SAMLMessageContext context, WebSSOProfileOptions options) throws SAMLException, MetadataProviderException, MessageEncodingException {

        // Verify we deal with a local SP
        if (!SPSSODescriptor.DEFAULT_ELEMENT_NAME.equals(context.getLocalEntityRole())) {
            throw new SAMLException("WebSSO can only be initialized for local SP, but localEntityRole is: " + context.getLocalEntityRole());
        }

        // Load the entities from the context
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        IDPSSODescriptor idpssoDescriptor = (IDPSSODescriptor) context.getPeerEntityRoleMetadata();
        ExtendedMetadata idpExtendedMetadata = context.getPeerExtendedMetadata();

        if (spDescriptor == null || idpssoDescriptor == null || idpExtendedMetadata == null) {
            throw new SAMLException("SPSSODescriptor, IDPSSODescriptor or IDPExtendedMetadata are not present in the SAMLContext");
        }

        SingleSignOnService ssoService = getSingleSignOnService(options, idpssoDescriptor, spDescriptor);
        AssertionConsumerService consumerService = getAssertionConsumerService(options, idpssoDescriptor, spDescriptor);
        AuthnRequest authRequest = getAuthnRequest(context, options, consumerService, ssoService);

        // TODO optionally implement support for conditions, subject

        context.setCommunicationProfileId(getProfileIdentifier());
        context.setOutboundMessage(authRequest);
        context.setOutboundSAMLMessage(authRequest);
        context.setPeerEntityEndpoint(ssoService);
        context.setPeerEntityRoleMetadata(idpssoDescriptor);
        context.setPeerExtendedMetadata(idpExtendedMetadata);

        if (options.getRelayState() != null) {
            context.setRelayState(options.getRelayState());
        }

        boolean sign = spDescriptor.isAuthnRequestsSigned() || idpssoDescriptor.getWantAuthnRequestsSigned();
        sendMessage(context, sign);

        SAMLMessageStorage messageStorage = context.getMessageStorage();
        if (messageStorage != null) {
            messageStorage.storeMessage(authRequest.getID(), authRequest);
        }

    }

    /**
     * Method determines SingleSignOn service (and thus binding) to be used to deliver AuthnRequest to the IDP.
     * When binding is specified in the WebSSOProfileOptions it is honored. Otherwise first suitable binding is used.
     *
     * @param options          user supplied preferences, binding attribute is used
     * @param idpssoDescriptor idp
     * @param spDescriptor     sp
     * @return service to send message to
     * @throws MetadataProviderException in case binding from the options is invalid or not found or when no default service can be found
     */
    protected SingleSignOnService getSingleSignOnService(WebSSOProfileOptions options, IDPSSODescriptor idpssoDescriptor, SPSSODescriptor spDescriptor) throws MetadataProviderException {

        // User specified value
        String userBinding = options.getBinding();

        // Find the endpoint
        List<SingleSignOnService> services = idpssoDescriptor.getSingleSignOnServices();
        for (SingleSignOnService service : services) {
            if (isEndpointSupported(service)) {
                if (userBinding != null) {
                    if (isEndpointMatching(service, userBinding)) {
                        log.debug("Found user specified binding {}", userBinding);
                        return service;
                    }
                } else {
                    // Use as a default
                    return service;
                }
            }
        }

        // No value found
        if (userBinding != null) {
            throw new MetadataProviderException("User specified binding " + userBinding + " is not supported by the IDP using profile " + getProfileIdentifier());
        } else {
            throw new MetadataProviderException("No supported binding " + userBinding + " was found for profile " + getProfileIdentifier());
        }

    }

    /**
     * Determines endpoint where should the identity provider return the SAML message. Endpoint also implies the used
     * binding. In case assertionConsumerIndex in the WebSSOProfileOptions is specified the endpoint with the given ID is used.
     * Otherwise assertionConsumerService marked as default is used when present, otherwise first found supported
     * assertionConsumerService is used.
     * <p>
     * In case endpoint determined by the webSSOProfileOptions index is not supported by the profile
     * an exception is raised.
     *
     * @param options          user supplied preferences
     * @param idpSSODescriptor idp, can be null when no IDP is known in advance
     * @param spDescriptor     sp
     * @return consumer service or null
     * @throws MetadataProviderException in case index supplied in options is invalid or unsupported or no supported consumer service can be found
     */
    protected AssertionConsumerService getAssertionConsumerService(WebSSOProfileOptions options, IDPSSODescriptor idpSSODescriptor, SPSSODescriptor spDescriptor) throws MetadataProviderException {

        List<AssertionConsumerService> services = spDescriptor.getAssertionConsumerServices();

        // Use user preference
        if (options.getAssertionConsumerIndex() != null) {
            for (AssertionConsumerService service : services) {
                if (options.getAssertionConsumerIndex().equals(service.getIndex())) {
                    if (!isEndpointSupported(service)) {
                        throw new MetadataProviderException("Endpoint designated by the value in the WebSSOProfileOptions is not supported by this profile");
                    } else {
                        log.debug("Using consumer service determined by user preference with binding {}", service.getBinding());
                        return service;
                    }
                }
            }
            throw new MetadataProviderException("AssertionConsumerIndex " + options.getAssertionConsumerIndex() + " not found for spDescriptor " + spDescriptor);
        }

        // Use default
        if (spDescriptor.getDefaultAssertionConsumerService() != null && isEndpointSupported(spDescriptor.getDefaultAssertionConsumerService())) {
            AssertionConsumerService service = spDescriptor.getDefaultAssertionConsumerService();
            log.debug("Using default consumer service with binding {}", service.getBinding());
            return service;
        }

        // Iterate and find first match
        if (services.size() > 0) {
            for (AssertionConsumerService service : services) {
                if (isEndpointSupported(service)) {
                    log.debug("Using first available consumer service with binding {}", service.getBinding());
                    return service;
                }
            }
        }

        throw new MetadataProviderException("Service provider has no assertion consumer service available for the selected profile " + spDescriptor);

    }

    /**
     * Determines whether given SingleSignOn service can be used together with this profile. Bindings POST, Artifact
     * and Redirect are supported for WebSSO.
     *
     * @param endpoint endpoint
     * @return true if endpoint is supported
     * @throws MetadataProviderException in case system can't verify whether endpoint is supported or not
     */
    protected boolean isEndpointSupported(SingleSignOnService endpoint) throws MetadataProviderException {
        return org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI.equals(endpoint.getBinding()) ||
                org.opensaml.common.xml.SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(endpoint.getBinding()) ||
                org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(endpoint.getBinding());
    }

    /**
     * Determines whether given AssertionConsumerService can be used to deliver messages consumable by this profile. Bindings
     * POST and Artifact are supported for WebSSO.
     *
     * @param endpoint endpoint
     * @return true if endpoint is supported
     * @throws MetadataProviderException in case system can't verify whether endpoint is supported or not
     */
    protected boolean isEndpointSupported(AssertionConsumerService endpoint) throws MetadataProviderException {
        return org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI.equals(endpoint.getBinding()) |
                org.opensaml.common.xml.SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(endpoint.getBinding());
    }

    /**
     * Returns AuthnRequest SAML message to be used to demand authentication from an IDP described using
     * idpEntityDescriptor, with an expected response to the assertionConsumer address.
     *
     * @param context           message context
     * @param options           preferences of message creation
     * @param assertionConsumer assertion consumer where the IDP should respond
     * @param bindingService    service used to deliver the request
     * @return authnRequest ready to be sent to IDP
     * @throws SAMLException             error creating the message
     * @throws MetadataProviderException error retreiving metadata
     */
    protected AuthnRequest getAuthnRequest(SAMLMessageContext context, WebSSOProfileOptions options,
                                           AssertionConsumerService assertionConsumer,
                                           SingleSignOnService bindingService) throws SAMLException, MetadataProviderException {

        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();

        request.setIsPassive(options.getPassive());
        request.setForceAuthn(options.getForceAuthN());
        request.setProviderName(options.getProviderName());
        request.setVersion(SAMLVersion.VERSION_20);

        buildCommonAttributes(context.getLocalEntityId(), request, bindingService);

        buildScoping(request, bindingService, options);
        builNameIDPolicy(request, options);
        buildAuthnContext(request, options);
        buildReturnAddress(request, assertionConsumer);

        return request;

    }

    /**
     * Fills the request with required AuthNContext according to selected options.
     *
     * @param request request to fill
     * @param options options driving generation of the element
     */
    protected void builNameIDPolicy(AuthnRequest request, WebSSOProfileOptions options) {

        if (options.getNameID() != null) {
            SAMLObjectBuilder<NameIDPolicy> builder = (SAMLObjectBuilder<NameIDPolicy>) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
            NameIDPolicy nameIDPolicy = builder.buildObject();
            nameIDPolicy.setFormat(options.getNameID());
            nameIDPolicy.setAllowCreate(options.isAllowCreate());
            nameIDPolicy.setSPNameQualifier(getSPNameQualifier());
            request.setNameIDPolicy(nameIDPolicy);
        }

    }

    /**
     * SAML-Core 2218, Specifies that returned subject identifier should be returned in the namespace of the given SP.
     *
     * @return by default returns null
     */
    protected String getSPNameQualifier() {
        return null;
    }

    /**
     * Fills the request with required AuthNContext according to selected options.
     *
     * @param request request to fill
     * @param options options driving generation of the element
     */
    protected void buildAuthnContext(AuthnRequest request, WebSSOProfileOptions options) {

        Collection<String> contexts = options.getAuthnContexts();
        if (contexts != null && contexts.size() > 0) {

            SAMLObjectBuilder<RequestedAuthnContext> builder = (SAMLObjectBuilder<RequestedAuthnContext>) builderFactory.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
            RequestedAuthnContext authnContext = builder.buildObject();
            authnContext.setComparison(options.getAuthnContextComparison());

            for (String context : contexts) {

                SAMLObjectBuilder<AuthnContextClassRef> contextRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
                AuthnContextClassRef authnContextClassRef = contextRefBuilder.buildObject();
                authnContextClassRef.setAuthnContextClassRef(context);
                authnContext.getAuthnContextClassRefs().add(authnContextClassRef);

            }

            request.setRequestedAuthnContext(authnContext);

        }

    }

    /**
     * Fills the request with assertion consumer service url and protocol binding based on assertionConsumer
     * to be used to deliver response from the IDP.
     *
     * @param request request
     * @param service service to deliver response to, building is skipped when null
     * @throws MetadataProviderException error retrieving metadata information
     */
    protected void buildReturnAddress(AuthnRequest request, AssertionConsumerService service) throws MetadataProviderException {
        if (service != null) {
            // AssertionConsumerServiceURL + ProtocolBinding is mutually exclusive with AssertionConsumerServiceIndex, we use the first one here
            if (service.getResponseLocation() != null) {
                request.setAssertionConsumerServiceURL(service.getResponseLocation());
            } else {
                request.setAssertionConsumerServiceURL(service.getLocation());
            }
            request.setProtocolBinding(getEndpointBinding(service));
        }
    }

    /**
     * Fills the request with information about scoping, including IDP in the scope IDP List.
     *
     * @param request    request to fill
     * @param serviceURI destination to send the request to
     * @param options    options driving generation of the element, contains list of allowed IDPs
     */
    protected void buildScoping(AuthnRequest request, SingleSignOnService serviceURI, WebSSOProfileOptions options) {

        if (options.isIncludeScoping() != null && options.isIncludeScoping()) {

            Set<String> idpEntityNames = options.getAllowedIDPs();
            IDPList idpList = buildIDPList(idpEntityNames, serviceURI);
            SAMLObjectBuilder<Scoping> scopingBuilder = (SAMLObjectBuilder<Scoping>) builderFactory.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
            Scoping scoping = scopingBuilder.buildObject();
            scoping.setIDPList(idpList);
            scoping.setProxyCount(options.getProxyCount());
            request.setScoping(scoping);

        }

    }

    /**
     * Builds an IdP List out of the idpEntityNames
     *
     * @param idpEntityNames The IdPs Entity IDs to include in the IdP List, no list is created when null
     * @param serviceURI     The binding service for an IdP for a specific binding. Should be null
     *                       if there is more than one IdP in the list or if the destination IdP is not known in
     *                       advance.
     * @return an IdP List or null when idpEntityNames is null
     */
    protected IDPList buildIDPList(Set<String> idpEntityNames, SingleSignOnService serviceURI) {

        if (idpEntityNames == null) {
            return null;
        }

        SAMLObjectBuilder<IDPEntry> idpEntryBuilder = (SAMLObjectBuilder<IDPEntry>) builderFactory.getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
        SAMLObjectBuilder<IDPList> idpListBuilder = (SAMLObjectBuilder<IDPList>) builderFactory.getBuilder(IDPList.DEFAULT_ELEMENT_NAME);
        IDPList idpList = idpListBuilder.buildObject();

        for (String entityID : idpEntityNames) {
            IDPEntry idpEntry = idpEntryBuilder.buildObject();
            idpEntry.setProviderID(entityID);
            idpList.getIDPEntrys().add(idpEntry);

            // The service URI would be null if the SP does not know in advance
            // to which IdP the request is sent to.
            if (serviceURI != null) {
                idpEntry.setLoc(serviceURI.getLocation());
            }
        }

        return idpList;

    }

}
