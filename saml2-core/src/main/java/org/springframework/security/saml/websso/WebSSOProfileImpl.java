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
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Class implements WebSSO profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect
 * bindings are supported.
 *
 * @author Vladimir Schafer
 */
public class WebSSOProfileImpl extends AbstractProfileBase implements WebSSOProfile {

    private static final int DEFAULT_PROXY_COUNT = 2;

    /**
     * Initializes the profile.
     *
     * @param metadata    metadata manager to be used
     * @param keyResolver key manager
     * @param signingKey  alias of key used for signing of assertions by local entity
     * @throws SAMLException error initializing the profile
     */
    public WebSSOProfileImpl(MetadataManager metadata, CredentialResolver keyResolver, String signingKey) throws SAMLException {
        super(metadata, signingKey, keyResolver);
    }

    /**
     * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the default binding.
     * Default IDP is used to send the request.
     *
     * @param options        values specified by caller to customize format of sent request
     * @param messageStorage object capable of storing and retreiving SAML messages
     * @param request        request
     * @param response       response
     * @throws SAMLException             error initializing SSO
     * @throws MetadataProviderException error retrieving needed metadata
     * @throws MessageEncodingException  error forming SAML message
     */
    public AuthnRequest initializeSSO(WebSSOProfileOptions options, SAMLMessageStorage messageStorage, HttpServletRequest request, HttpServletResponse response) throws SAMLException, MetadataProviderException, MessageEncodingException {
        // Initialize IDP and SP
        String idpId = options.getIdp();
        if (idpId == null) {
            idpId = metadata.getDefaultIDP();
        }
        IDPSSODescriptor idpssoDescriptor = getIDPDescriptor(idpId);
        SPSSODescriptor spDescriptor = getSPDescriptor(metadata.getHostedSPName());
        String binding = SAMLUtil.getLoginBinding(options, idpssoDescriptor, spDescriptor);

        AssertionConsumerService assertionConsubmerForBinding = SAMLUtil.getAssertionConsumerForBinding(spDescriptor, binding);
        SingleSignOnService bindingService = SAMLUtil.getSSOServiceForBinding(idpssoDescriptor, binding);
        AuthnRequest authRequest = getAuthnRequest(options, idpId, assertionConsubmerForBinding, bindingService);

        // TODO optionally implement support for authncontext, conditions, nameIDpolicy, subject

        sendMessage(messageStorage, idpssoDescriptor.getWantAuthnRequestsSigned(), authRequest, bindingService, response);
        return authRequest;
    }

    /**
     * Returns AuthnRequest SAML message to be used to demand authentication from an IDP described using
     * idpEntityDescriptor, with an expected response to the assertionConsumer address.
     *
     * @param options           preferences of message creation
     * @param idpEntityId       entity ID of the IDP
     * @param assertionConsumer assertion consumer where the IDP should respond
     * @param bindingService    service used to deliver the request
     * @return authnRequest ready to be sent to IDP
     * @throws SAMLException             error creating the message
     * @throws MetadataProviderException error retreiving metadata
     */
    protected AuthnRequest getAuthnRequest(WebSSOProfileOptions options, String idpEntityId, AssertionConsumerService assertionConsumer, SingleSignOnService bindingService) throws SAMLException, MetadataProviderException {
        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();

        request.setIsPassive(options.getPassive());
        request.setForceAuthn(options.getForceAuthN());

        buildCommonAttributes(request, bindingService);
        buildScoping(request, idpEntityId, bindingService, options);
        buildReturnAddress(request, assertionConsumer);

        return request;
    }

    /**
     * Fills the request with assertion consumer service url and protocol binding based on assertionConsumer
     * to be used to deliver response from the IDP.
     *
     * @param request request
     * @param service service to deliver response to
     * @throws MetadataProviderException error retrieving metadata information
     */
    private void buildReturnAddress(AuthnRequest request, AssertionConsumerService service) throws MetadataProviderException {
        request.setVersion(SAMLVersion.VERSION_20);
        request.setAssertionConsumerServiceURL(service.getLocation());
        request.setProtocolBinding(service.getBinding());
    }

    /**
     * Fills the request with information about scoping, including IDP in the scope IDP List.
     *
     * @param request     request to fill
     * @param idpEntityId id of the idp entity
     * @param serviceURI  destination to send the request to
     * @param options     options driving generation of the element
     */
    protected void buildScoping(AuthnRequest request, String idpEntityId, SingleSignOnService serviceURI, WebSSOProfileOptions options) {

        if (options.isIncludeScoping()) {

            SAMLObjectBuilder<IDPEntry> idpEntryBuilder = (SAMLObjectBuilder<IDPEntry>) builderFactory.getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
            IDPEntry idpEntry = idpEntryBuilder.buildObject();
            idpEntry.setProviderID(idpEntityId);
            idpEntry.setLoc(serviceURI.getLocation());

            SAMLObjectBuilder<IDPList> idpListBuilder = (SAMLObjectBuilder<IDPList>) builderFactory.getBuilder(IDPList.DEFAULT_ELEMENT_NAME);
            IDPList idpList = idpListBuilder.buildObject();
            idpList.getIDPEntrys().add(idpEntry);

            SAMLObjectBuilder<Scoping> scopingBuilder = (SAMLObjectBuilder<Scoping>) builderFactory.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
            Scoping scoping = scopingBuilder.buildObject();
            scoping.setIDPList(idpList);

            if (options.isAllowProxy()) {
                scoping.setProxyCount(DEFAULT_PROXY_COUNT);
            }

            request.setScoping(scoping);

        }

    }

}
