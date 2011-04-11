/*
 * Copyright 2011 Jonathan Tellier, Vladimir Schaefer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.saml2.ecp.Request;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.util.SOAPHelper;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.SAMLMessageStorage;

import java.util.Set;

/**
 * Class implementing the SAML ECP Profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. PAOS Binding is supported
 *
 * @author Jonathan Tellier, Vladimir Schaefer
 */
public class WebSSOProfileECPImpl extends WebSSOProfileImpl {

    public WebSSOProfileECPImpl() {
    }

    public WebSSOProfileECPImpl(SAMLProcessor processor, MetadataManager manager) {
        super(processor, manager);
    }

    @Override
    public void sendAuthenticationRequest(SAMLMessageContext context, WebSSOProfileOptions options, SAMLMessageStorage messageStorage)
            throws SAMLException, MetadataProviderException, MessageEncodingException {

        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        AssertionConsumerService assertionConsumer = getAssertionConsumerService(null, spDescriptor, options, SAMLConstants.SAML2_PAOS_BINDING_URI);

        // The last parameter refers to the IdP that should receive the message. However,
        // in ECP, we don't know in advance which IdP will be contacted.
        AuthnRequest authRequest = getAuthnRequest(context, options, assertionConsumer, null);

        context.setCommunicationProfileId(SAMLConstants.SAML2_PAOS_BINDING_URI);
        context.setOutboundMessage(getEnvelope());
        context.setOutboundSAMLMessage(authRequest);

        SOAPHelper.addHeaderBlock(context, getPAOSRequest(assertionConsumer));
        SOAPHelper.addHeaderBlock(context, getECPRequest(context, options));

        if (context.getRelayState() != null) {
            SOAPHelper.addHeaderBlock(context, getRelayState(context.getRelayState()));
        }

        sendMessage(context, spDescriptor.isAuthnRequestsSigned(), SAMLConstants.SAML2_PAOS_BINDING_URI);
        messageStorage.storeMessage(authRequest.getID(), authRequest);

    }

    protected org.opensaml.liberty.paos.Request getPAOSRequest(AssertionConsumerService assertionConsumer) {

        SAMLObjectBuilder<org.opensaml.liberty.paos.Request> paosRequestBuilder = (SAMLObjectBuilder<org.opensaml.liberty.paos.Request>) builderFactory.getBuilder(org.opensaml.liberty.paos.Request.DEFAULT_ELEMENT_NAME);
        org.opensaml.liberty.paos.Request paosRequest = paosRequestBuilder.buildObject();

        paosRequest.setSOAP11Actor(Request.SOAP11_ACTOR_NEXT);
        paosRequest.setSOAP11MustUnderstand(true);
        paosRequest.setResponseConsumerURL(assertionConsumer.getLocation());
        paosRequest.setService(SAMLConstants.SAML20ECP_NS);

        return paosRequest;

    }

    protected Request getECPRequest(SAMLMessageContext context, WebSSOProfileOptions options) {

        SAMLObjectBuilder<Request> ecpRequestBuilder = (SAMLObjectBuilder<Request>) builderFactory.getBuilder(Request.DEFAULT_ELEMENT_NAME);
        Request ecpRequest = ecpRequestBuilder.buildObject();

        ecpRequest.setSOAP11Actor(Request.SOAP11_ACTOR_NEXT);
        ecpRequest.setSOAP11MustUnderstand(true);

        ecpRequest.setPassive(options.getPassive());
        ecpRequest.setProviderName(options.getProviderName());
        ecpRequest.setIssuer(getIssuer(context.getLocalEntityId()));

        Set<String> idpEntityNames = options.getAllowedIDPs();
        if (options.isIncludeScoping() && idpEntityNames != null) {
            ecpRequest.setIDPList(buildIDPList(idpEntityNames, null));
        }

        return ecpRequest;

    }

    protected Envelope getEnvelope() {

        SOAPObjectBuilder<Envelope> envelopeBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        return envelopeBuilder.buildObject();

    }

    /**
     * Method creates a relayState element usable with the ECP profile.
     * @param relayStateValue value to include, mustn't be null
     * @return relay state object
     */
    protected RelayState getRelayState(String relayStateValue) {

        if (relayStateValue == null) {
            throw new IllegalArgumentException("RelayStateValue can't be null");
        }
        if (relayStateValue.length() > 80) {
            throw new IllegalArgumentException("Relay state can't exceed size 80 when using ECP profile");
        }

        SAMLObjectBuilder<RelayState> relayStateBuilder = (SAMLObjectBuilder<RelayState>) builderFactory.getBuilder(RelayState.DEFAULT_ELEMENT_NAME);
        RelayState relayState = relayStateBuilder.buildObject();
        relayState.setSOAP11Actor(RelayState.SOAP11_ACTOR_NEXT);
        relayState.setSOAP11MustUnderstand(true);
        relayState.setValue(relayStateValue);
        return relayState;

    }

}