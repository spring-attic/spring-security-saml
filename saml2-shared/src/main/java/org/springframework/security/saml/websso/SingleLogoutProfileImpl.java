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
package org.springframework.security.saml.websso;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Implementation of the SAML 2.0 Single Logout profile.
 *
 * @author Vladimir Schäfer
 */
public class SingleLogoutProfileImpl extends AbstractProfileBase implements SingleLogoutProfile {

    /**
     * Class logger.
     */
    private final static Logger log = LoggerFactory.getLogger(SingleLogoutProfileImpl.class);

    /**
     * Initializes the profile.
     *
     * @param metadata   metadata manager to be used
     * @param keyManager key manager
     * @param signingKey alias of key used for signing of assertions by local entity
     * @throws SAMLException error initializing the profile
     */
    public SingleLogoutProfileImpl(MetadataManager metadata, KeyStoreCredentialResolver keyManager, String signingKey) throws SAMLException {
        super(metadata, signingKey, keyManager, new ExplicitKeySignatureTrustEngine(new MetadataCredentialResolver(metadata), Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver()));
    }

    public void initializeLogout(SAMLCredential credential, SAMLMessageStorage messageStorage, HttpServletRequest request, HttpServletResponse response) throws SAMLException, MetadataProviderException, MessageEncodingException {

        // If no user is logged in we do not initialize the protocol.
        if (credential == null) {
            return;
        }

        IDPSSODescriptor idpDescriptor = getIDPDescriptor(credential.getIDPEntityID());
        SPSSODescriptor spDescriptor = getSPDescriptor(metadata.getHostedSPName());
        String binding = SAMLUtil.getLogoutBinding(idpDescriptor, spDescriptor);

        SingleLogoutService logoutServiceIDP = SAMLUtil.getLogoutServiceForBinding(idpDescriptor, binding);
        LogoutRequest logoutRequest = getLogoutRequest(credential, logoutServiceIDP);
        sendMessage(messageStorage, true, logoutRequest, logoutServiceIDP, response);

    }

    /**
     * Returns logout request message ready to be sent to the IDP.
     *
     * @param credential     information about assertions used to log current user in
     * @param bindingService service used to deliver the request
     * @return logoutRequest to be sent to IDP
     * @throws SAMLException             error creating the message
     * @throws MetadataProviderException error retreiving metadata
     */
    protected LogoutRequest getLogoutRequest(SAMLCredential credential, Endpoint bindingService) throws SAMLException, MetadataProviderException {

        SAMLObjectBuilder<LogoutRequest> builder = (SAMLObjectBuilder<LogoutRequest>) builderFactory.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
        LogoutRequest request = builder.buildObject();
        buildCommonAttributes(request, bindingService);

        // Add session indexes
        SAMLObjectBuilder<SessionIndex> sessionIndexBuilder = (SAMLObjectBuilder<SessionIndex>) builderFactory.getBuilder(SessionIndex.DEFAULT_ELEMENT_NAME);
        for (AuthnStatement statement : credential.getAuthenticationAssertion().getAuthnStatements()) {
            SessionIndex index = sessionIndexBuilder.buildObject();
            index.setSessionIndex(statement.getSessionIndex());
            request.getSessionIndexes().add(index);
        }

        if (request.getSessionIndexes().size() == 0) {
            throw new SAMLException("No session indexes to logout user for were found");
        }

        SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setFormat(credential.getNameID().getFormat());
        nameID.setNameQualifier(credential.getNameID().getNameQualifier());
        nameID.setSPNameQualifier(credential.getNameID().getSPNameQualifier());
        nameID.setSPProvidedID(credential.getNameID().getSPProvidedID());
        nameID.setValue(credential.getNameID().getValue());
        request.setNameID(nameID);

        return request;

    }

    public boolean processLogoutRequest(BasicSAMLMessageContext context, HttpServletRequest request, HttpServletResponse response) throws SAMLException {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void processLogoutResponse(BasicSAMLMessageContext context, SAMLMessageStorage protocolCache) throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException {

        SAMLObject message = context.getInboundSAMLMessage();

        // Verify type
        if (!(message instanceof LogoutResponse)) {
            log.debug("Received response is not of a Response object type");
            throw new SAMLException("Error validating SAML response");
        }
        LogoutResponse response = (LogoutResponse) message;

        // Verify signature of the response if present
        if (response.getSignature() != null) {
            verifySignature(response.getSignature(), context.getPeerEntityId());
        }

        // Verify issue time
        DateTime time = response.getIssueInstant();
        if (!isDateTimeSkewValid(DEFAULT_RESPONSE_SKEW, time)) {
            log.debug("Response issue time is either too old or with date in the future");
            throw new SAMLException("Error validating SAML response");
        }

        // Verify response to field if present, set request if correct
        // The inResponseTo field is optional, SAML 2.0 Core, 1542 
        if (response.getInResponseTo() != null) {
            XMLObject xmlObject = protocolCache.retreiveMessage(response.getInResponseTo());
            if (xmlObject == null) {
                log.debug("InResponseToField doesn't correspond to sent message", response.getInResponseTo());
                throw new SAMLException("Error validating SAML response");
            } else if (xmlObject instanceof LogoutRequest) {
            } else {
                log.debug("Sent request was of different type then received response", response.getInResponseTo());
                throw new SAMLException("Error validating SAML response");
            }
        }

        // Verify destination
        if (response.getDestination() != null) {
            SPSSODescriptor localDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();

            // Check if destination is correct on this SP
            List<SingleLogoutService> services = localDescriptor.getSingleLogoutServices();
            boolean found = false;
            for (SingleLogoutService service : services) {
                if (response.getDestination().equals(service.getLocation()) &&
                        context.getInboundSAMLProtocol().equals(service.getBinding())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                log.debug("Destination of the response was not the expected value", response.getDestination());
                throw new SAMLException("Error validating SAML response");
            }
        }

        // Verify issuer
        if (response.getIssuer() != null) {
            Issuer issuer = response.getIssuer();
            verifyIssuer(issuer, context);
        }

        // Verify status
        String statusCode = response.getStatus().getStatusCode().getValue();
        if (StatusCode.SUCCESS_URI.equals(statusCode)) {
            log.trace("Single Logout was successful");
        } else if (StatusCode.PARTIAL_LOGOUT_URI.equals(statusCode)) {
            log.trace("Single Logout was partially successful");
        } else {
            String[] logMessage = new String[2];
            logMessage[0] = response.getStatus().getStatusCode().getValue();
            StatusMessage message1 = response.getStatus().getStatusMessage();
            if (message1 != null) {
                logMessage[1] = message1.getMessage();
            }
            log.debug("Received LogoutResponse has invalid status code", logMessage);
            throw new SAMLException("SAML status is not success code");
        }

    }

}
