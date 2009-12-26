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
import org.opensaml.common.SAMLVersion;
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
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.security.credential.CredentialResolver;
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
     * @param credentialResolver key manager
     * @param signingKey alias of key used for signing of assertions by local entity
     * @throws SAMLException error initializing the profile
     */
    public SingleLogoutProfileImpl(MetadataManager metadata, CredentialResolver credentialResolver, String signingKey) throws SAMLException {
        super(metadata, signingKey, credentialResolver, new ExplicitKeySignatureTrustEngine(new MetadataCredentialResolver(metadata), Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver()));
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

    public boolean processLogoutRequest(SAMLCredential credential, BasicSAMLMessageContext context, HttpServletResponse response) throws SAMLException, MetadataProviderException, MessageEncodingException {

        SAMLObject message = context.getInboundSAMLMessage();

        // Verify type
        if (message == null || !(message instanceof LogoutRequest)) {
            log.warn("Received request is not of a LogoutRequest object type");
            throw new SAMLException("Error validating SAML request");
        }
        LogoutRequest logoutRequest = (LogoutRequest) message;

        // Verify signature of the response if present
        if (logoutRequest.getSignature() != null) {
            try {
                verifySignature(logoutRequest.getSignature(), context.getPeerEntityId());
            } catch (org.opensaml.xml.security.SecurityException e) {
                log.warn("Validation of signature in LogoutRequest has failed, id: " + context.getInboundSAMLMessageId());
                Status status = getStatus(StatusCode.REQUEST_DENIED_URI, "Message signature is invalid");
                sendLogoutResponse(status, context, response);
                return false;
            } catch (ValidationException e) {
                log.warn("Validation of signature in LogoutRequest has failed, id: " + context.getInboundSAMLMessageId());
                Status status = getStatus(StatusCode.REQUEST_DENIED_URI, "Message signature is invalid");
                sendLogoutResponse(status, context, response);
                return false;
            }
        }

        // Verify destination
        if (logoutRequest.getDestination() != null) {
            SPSSODescriptor localDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();

            // Check if destination is correct on this SP
            List<SingleLogoutService> services = localDescriptor.getSingleLogoutServices();
            boolean found = false;
            for (SingleLogoutService service : services) {
                if (logoutRequest.getDestination().equals(service.getLocation()) &&
                        context.getCommunicationProfileId().equals(service.getBinding())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                log.warn("Destination of the request was not the expected value: ", logoutRequest.getDestination());
                Status status = getStatus(StatusCode.REQUEST_DENIED_URI, "Destination URL of the request is invalid");
                sendLogoutResponse(status, context, response);
                return false;
            }
        }

        // Verify issuer
        if (logoutRequest.getIssuer() != null) {
            try {
                Issuer issuer = logoutRequest.getIssuer();
                verifyIssuer(issuer, context);
            } catch (SAMLException e) {
                log.warn("Response issue time is either too old or with date in the future, id: " + context.getInboundSAMLMessageId());
                Status status = getStatus(StatusCode.REQUEST_DENIED_URI, "Issuer of the message is unknown");
                sendLogoutResponse(status, context, response);
                return false;
            }
        }

        // Verify issue time
        DateTime time = logoutRequest.getIssueInstant();
        if (!isDateTimeSkewValid(DEFAULT_RESPONSE_SKEW, time)) {
            log.warn("Response issue time is either too old or with date in the future, id: " + context.getInboundSAMLMessageId());
            Status status = getStatus(StatusCode.REQUESTER_URI, "Message has been issued too long time ago");
            sendLogoutResponse(status, context, response);
            return false;
        }

        // Check whether any user is logged in
        if (credential == null) {
            Status status = getStatus(StatusCode.UNKNOWN_PRINCIPAL_URI, "No user is logged in");
            sendLogoutResponse(status, context, response);
            return false;
        }

        // TODO
        if (logoutRequest.getNotOnOrAfter() != null) {

        }

        // Find index for which the logout is requested
        boolean indexFound = false;
        if (logoutRequest.getSessionIndexes() != null && logoutRequest.getSessionIndexes().size() > 0) {
            for (AuthnStatement statement : credential.getAuthenticationAssertion().getAuthnStatements()) {
                String statementIndex = statement.getSessionIndex();
                if (statementIndex != null) {
                    for (SessionIndex index : logoutRequest.getSessionIndexes()) {
                        if (statementIndex.equals(index.getSessionIndex())) {
                            indexFound = true;
                        }
                    }
                }
            }
        } else {
            indexFound = true;
        }

        // Fail if sessionIndex is not found in any assertion
        if (!indexFound) {
            Status status = getStatus(StatusCode.REQUESTER_URI, "The requested SessionIndex was not found");
            sendLogoutResponse(status, context, response);
            return false;
        }

        try {
            // Fail if NameId doesn't correspond to the currently logged user
            NameID nameID = getNameID(logoutRequest);
            if (nameID == null || !equalsNameID(credential.getNameID(), nameID)) {
                Status status = getStatus(StatusCode.UNKNOWN_PRINCIPAL_URI, "The requested NameID is invalid");
                sendLogoutResponse(status, context, response);
                return false;
            }
        } catch (DecryptionException e) {
            Status status = getStatus(StatusCode.RESPONDER_URI, "The NameID can't be decrypted");
            sendLogoutResponse(status, context, response);
            return false;
        }

        // Message is valid, let's logout
        Status status = getStatus(StatusCode.SUCCESS_URI, null);
        sendLogoutResponse(status, context, response);
        return true;

    }

    protected void sendLogoutResponse(Status status, BasicSAMLMessageContext context, HttpServletResponse response) throws MetadataProviderException, SAMLException, MessageEncodingException {

        SAMLObjectBuilder<LogoutResponse> responseBuilder = (SAMLObjectBuilder<LogoutResponse>) builderFactory.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
        LogoutResponse logoutResponse = responseBuilder.buildObject();

        IDPSSODescriptor idpDescriptor = getIDPDescriptor(context.getPeerEntityId());
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        String binding = SAMLUtil.getLogoutBinding(idpDescriptor, spDescriptor);
        SingleLogoutService logoutService = SAMLUtil.getLogoutServiceForBinding(idpDescriptor, binding);

        logoutResponse.setID(generateID());
        logoutResponse.setIssuer(getIssuer());
        logoutResponse.setVersion(SAMLVersion.VERSION_20);
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setInResponseTo(context.getOutboundSAMLMessageId());
        logoutResponse.setDestination(logoutService.getLocation());

        logoutResponse.setStatus(status);

        sendMessage(true, logoutResponse, logoutService, response);

    }

    private boolean equalsNameID(NameID a, NameID b) {
        boolean equals = !differ(a.getSPProvidedID(), b.getSPProvidedID());
        equals = equals && !differ(a.getValue(), b.getValue());
        equals = equals && !differ(a.getFormat(), b.getFormat());
        equals = equals && !differ(a.getNameQualifier(), b.getNameQualifier());
        equals = equals && !differ(a.getSPNameQualifier(), b.getSPNameQualifier());
        equals = equals && !differ(a.getSPProvidedID(), b.getSPProvidedID());
        return equals;
    }

    private boolean differ(Object a, Object b) {
        if (a == null) {
            return b != null;
        } else {
            return !a.equals(b);
        }
    }

    protected NameID getNameID(LogoutRequest request) throws DecryptionException {
        NameID id;
        if (request.getEncryptedID() != null) {
            id = (NameID) decryper.decrypt(request.getEncryptedID());
        } else {
            id = request.getNameID();
        }
        return id;
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
                        context.getCommunicationProfileId().equals(service.getBinding())) {
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
            log.warn("Received LogoutResponse has invalid status code", logMessage);
        }

    }

}
