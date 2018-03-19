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

import java.util.Set;

import org.opensaml.compat.MetadataProviderException;
import org.opensaml.compat.SOAPHelper;
import org.opensaml.compat.transport.http.HTTPOutTransport;
import org.opensaml.liberty.paos.Request;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.soap.common.SOAPObjectBuilder;
import org.opensaml.soap.soap11.Envelope;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.storage.SAMLMessageStorage;

/**
 * Class implementing the SAML ECP Profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. PAOS Binding is supported
 *
 * @author Jonathan Tellier, Vladimir Schaefer
 */
public class WebSSOProfileECPImpl extends WebSSOProfileImpl {

    @Override
    public String getProfileIdentifier() {
        return org.springframework.security.saml.SAMLConstants.SAML2_ECP_PROFILE_URI;
    }

    @Override
    public void sendAuthenticationRequest(SAMLMessageContext context, WebSSOProfileOptions options)
        throws SAMLException, MetadataProviderException, MessageEncodingException {

        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        AssertionConsumerService assertionConsumer = getAssertionConsumerService(options, null, spDescriptor);

        // The last parameter refers to the IdP that should receive the message. However,
        // in ECP, we don't know in advance which IdP will be contacted.
        AuthnRequest authRequest = getAuthnRequest(context, options, assertionConsumer, null);

        context.setCommunicationProfileId(getProfileIdentifier());
        context.setOutboundMessage(getEnvelope());
        context.setOutboundSAMLMessage(authRequest);

        SOAPHelper.addHeaderBlock(context, getPAOSRequest(assertionConsumer));
        SOAPHelper.addHeaderBlock(context, getECPRequest(context, options));

        sendMessage(context, spDescriptor.isAuthnRequestsSigned(), SAMLConstants.SAML2_PAOS_BINDING_URI);

        HTTPOutTransport outTransport = (HTTPOutTransport) context.getOutboundMessageTransport();
        outTransport.setHeader("Content-Type", "application/vnd.paos+xml");

        SAMLMessageStorage messageStorage = context.getMessageStorage();
        if (messageStorage != null) {
            messageStorage.storeMessage(authRequest.getID(), authRequest);
        }

    }

    @Override
    protected boolean isEndpointSupported(AssertionConsumerService endpoint) {
        return SAMLConstants.SAML2_PAOS_BINDING_URI.equals(endpoint.getBinding());
    }

    @Override
    protected boolean isEndpointSupported(SingleSignOnService endpoint) {
        return false;
    }

    protected org.opensaml.liberty.paos.Request getPAOSRequest(AssertionConsumerService assertionConsumer) {

        SAMLObjectBuilder<Request> paosRequestBuilder = (SAMLObjectBuilder<org.opensaml.liberty.paos.Request>) builderFactory.getBuilder(org.opensaml.liberty.paos.Request.DEFAULT_ELEMENT_NAME);
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


//        ecpRequest.setPassive(options.getPassive());
//        ecpRequest.setProviderName(options.getProviderName());
//        ecpRequest.setIssuer(getIssuer(context.getLocalEntityId()));

        Set<String> idpEntityNames = options.getAllowedIDPs();
        if (options.isIncludeScoping() && idpEntityNames != null) {
            //ecpRequest.setIDPList(buildIDPList(idpEntityNames, null));
        }
        throw new UnsupportedOperationException("not resolved");

        //return ecpRequest;

    }

    protected Envelope getEnvelope() {

        SOAPObjectBuilder<Envelope> envelopeBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        return envelopeBuilder.buildObject();

    }

}