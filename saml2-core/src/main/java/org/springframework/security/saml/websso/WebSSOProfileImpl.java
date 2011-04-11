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
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;

import java.util.Collection;
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

    /**
     * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the default binding.
     * Default IDP is used to send the request.
     *
     * @param options        values specified by caller to customize format of sent request
     * @param messageStorage object capable of storing and retreiving SAML messages
     * @throws SAMLException             error initializing SSO
     * @throws MetadataProviderException error retrieving needed metadata
     * @throws MessageEncodingException  error forming SAML message
     */
    public void sendAuthenticationRequest(SAMLMessageContext context, WebSSOProfileOptions options, SAMLMessageStorage messageStorage) throws SAMLException, MetadataProviderException, MessageEncodingException {

        // Verify we deal with a local SP
        if (!SPSSODescriptor.DEFAULT_ELEMENT_NAME.equals(context.getLocalEntityRole())) {
            throw new SAMLException("WebSSO can only be initialized for local SP, but localEntityRole is: " + context.getLocalEntityRole());
        }

        // Initialize IDP based on options or use default
        String idpId = options.getIdp();
        if (idpId == null) {
            idpId = metadata.getDefaultIDP();
        }

        // Load the entities
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        IDPSSODescriptor idpssoDescriptor = getIDPDescriptor(idpId);
        ExtendedMetadata idpExtendedMetadata = metadata.getExtendedMetadata(idpId);
        SingleSignOnService ssoService = getSingleSignOnService(idpssoDescriptor, spDescriptor, options);
        AssertionConsumerService consumerService = getAssertionConsumerService(idpssoDescriptor, spDescriptor, options, null);
        AuthnRequest authRequest = getAuthnRequest(context, options, consumerService, ssoService);

        // TODO optionally implement support for conditions, subject

        context.setCommunicationProfileId(ssoService.getBinding());
        context.setOutboundMessage(authRequest);
        context.setOutboundSAMLMessage(authRequest);
        context.setPeerEntityEndpoint(ssoService);
        context.setPeerEntityId(idpssoDescriptor.getID());
        context.setPeerEntityRoleMetadata(idpssoDescriptor);
        context.setPeerExtendedMetadata(idpExtendedMetadata);

        boolean sign = spDescriptor.isAuthnRequestsSigned() || idpssoDescriptor.getWantAuthnRequestsSigned();
        sendMessage(context, sign);
        messageStorage.storeMessage(authRequest.getID(), authRequest);

    }

    /**
     * Method determines SingleSignOn service used to deliver AuthNRequest to the IDP. Service also determines the used binding.
     * When set value binding from WebSSOProfileOptions is used to prioritize the service.
     *
     * @param idpssoDescriptor idp
     * @param spDescriptor     sp
     * @param options          user supplied preferences
     * @return service to send message to
     * @throws MetadataProviderException in case service can't be determined
     */
    protected SingleSignOnService getSingleSignOnService(IDPSSODescriptor idpssoDescriptor, SPSSODescriptor spDescriptor, WebSSOProfileOptions options) throws MetadataProviderException {
        return SAMLUtil.getSSOServiceForBinding(idpssoDescriptor, SAMLUtil.getLoginBinding(options, idpssoDescriptor, spDescriptor));
    }

    /**
     * Determines assertion consumer service where IDP should send reply to the AuthnRequest.
     *
     * @param idpssoDescriptor idp, can be null when no IDP is known in advance
     * @param spDescriptor     sp
     * @param options          user supplied preferences
     * @param binding binding to be used, overrides other settings
     * @return consumer service or null
     * @throws MetadataProviderException in case index supplied in options is invalid or no consumer service can be found
     */
    protected AssertionConsumerService getAssertionConsumerService(IDPSSODescriptor idpssoDescriptor, SPSSODescriptor spDescriptor, WebSSOProfileOptions options, String binding) throws MetadataProviderException {
        return SAMLUtil.getAssertionConsumerForBinding(idpssoDescriptor, spDescriptor, options, binding);
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
            request.setAssertionConsumerServiceURL(service.getLocation());
            request.setProtocolBinding(service.getBinding());
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

        if (options.isIncludeScoping()) {

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
