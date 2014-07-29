/*
 * Copyright 2009 Vladimir Schaefer
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
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLStatusException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.Assert;

import java.util.List;

import static org.springframework.security.saml.util.SAMLUtil.isDateTimeSkewValid;

/**
 * Implementation of the SAML 2.0 Single Logout profile.
 *
 * @author Vladimir Schaefer
 */
public class SingleLogoutProfileImpl extends AbstractProfileBase implements SingleLogoutProfile {

    @Override
    public String getProfileIdentifier() {
        return SAMLConstants.SAML2_SLO_PROFILE_URI;
    }

    public void sendLogoutRequest(SAMLMessageContext context, SAMLCredential credential) throws SAMLException, MetadataProviderException, MessageEncodingException {

        // If no user is logged in we do not initialize the protocol.
        if (credential == null) {
            return;
        }

        IDPSSODescriptor idpDescriptor = (IDPSSODescriptor) context.getPeerEntityRoleMetadata();
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        String binding = SAMLUtil.getLogoutBinding(idpDescriptor, spDescriptor);

        SingleLogoutService logoutServiceIDP = SAMLUtil.getLogoutServiceForBinding(idpDescriptor, binding);
        LogoutRequest logoutRequest = getLogoutRequest(context, credential, logoutServiceIDP);

        context.setCommunicationProfileId(getProfileIdentifier());
        context.setOutboundMessage(logoutRequest);
        context.setOutboundSAMLMessage(logoutRequest);
        context.setPeerEntityEndpoint(logoutServiceIDP);

        boolean signMessage = context.getPeerExtendedMetadata().isRequireLogoutRequestSigned();
        sendMessage(context, signMessage);

        SAMLMessageStorage messageStorage = context.getMessageStorage();
        if (messageStorage != null) {
            messageStorage.storeMessage(logoutRequest.getID(), logoutRequest);
        }

    }

    /**
     * Returns logout request message ready to be sent to the IDP.
     *
     * @param context        message context
     * @param credential     information about assertions used to log current user in
     * @param bindingService service used to deliver the request
     * @return logoutRequest to be sent to IDP
     * @throws SAMLException             error creating the message
     * @throws MetadataProviderException error retrieving metadata
     */
    protected LogoutRequest getLogoutRequest(SAMLMessageContext context, SAMLCredential credential, Endpoint bindingService) throws SAMLException, MetadataProviderException {

        SAMLObjectBuilder<LogoutRequest> builder = (SAMLObjectBuilder<LogoutRequest>) builderFactory.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
        LogoutRequest request = builder.buildObject();
        buildCommonAttributes(context.getLocalEntityId(), request, bindingService);

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

    public boolean processLogoutRequest(SAMLMessageContext context, SAMLCredential credential) throws SAMLException {

        SAMLObject message = context.getInboundSAMLMessage();

        // Verify type
        if (message == null || !(message instanceof LogoutRequest)) {
            throw new SAMLException("Message is not of a LogoutRequest object type");
        }

        LogoutRequest logoutRequest = (LogoutRequest) message;

        // Make sure request was authenticated if required, authentication is done as part of the binding processing
        if (!context.isInboundSAMLMessageAuthenticated() && context.getLocalExtendedMetadata().isRequireLogoutRequestSigned()) {
            throw new SAMLStatusException(StatusCode.REQUEST_DENIED_URI, "LogoutRequest is required to be signed by the entity policy");
        }

        // Verify destination
        try {
            verifyEndpoint(context.getLocalEntityEndpoint(), logoutRequest.getDestination());
        } catch (SAMLException e) {
            throw new SAMLStatusException(StatusCode.REQUEST_DENIED_URI, "Destination of the LogoutRequest does not match any of the single logout endpoints");
        }

        // Verify issuer
        try {
            if (logoutRequest.getIssuer() != null) {
                Issuer issuer = logoutRequest.getIssuer();
                verifyIssuer(issuer, context);
            }
        } catch (SAMLException e) {
            throw new SAMLStatusException(StatusCode.REQUEST_DENIED_URI, "Issuer of the LogoutRequest is unknown");
        }

        // Verify issue time
        DateTime time = logoutRequest.getIssueInstant();
        if (!isDateTimeSkewValid(getResponseSkew(), time)) {
            throw new SAMLStatusException(StatusCode.REQUESTER_URI, "LogoutRequest issue instant is either too old or with date in the future");
        }

        // Check whether any user is logged in
        if (credential == null) {
            throw new SAMLStatusException(StatusCode.UNKNOWN_PRINCIPAL_URI, "No user is logged in");
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

            // Check logout request still valid and store request
            //if (logoutRequest.getNotOnOrAfter() != null) {
            // TODO store request for assertions possibly arriving later
            //}

            throw new SAMLStatusException(StatusCode.REQUESTER_URI, "The SessionIndex was not found");

        }

        try {
            // Fail if NameId doesn't correspond to the currently logged user
            NameID nameID = getNameID(context, logoutRequest);
            if (nameID == null || !equalsNameID(credential.getNameID(), nameID)) {
                throw new SAMLStatusException(StatusCode.UNKNOWN_PRINCIPAL_URI, "The requested NameID is invalid");
            }
        } catch (DecryptionException e) {
            throw new SAMLStatusException(StatusCode.RESPONDER_URI, "The NameID can't be decrypted", e);
        }

        return true;

    }

    public void sendLogoutResponse(SAMLMessageContext context, String statusCode, String statusMessage) throws MetadataProviderException, SAMLException, MessageEncodingException {

        SAMLObjectBuilder<LogoutResponse> responseBuilder = (SAMLObjectBuilder<LogoutResponse>) builderFactory.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
        LogoutResponse logoutResponse = responseBuilder.buildObject();

        IDPSSODescriptor idpDescriptor = SAMLUtil.getIDPDescriptor(metadata, context.getPeerEntityId());
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        String binding = SAMLUtil.getLogoutBinding(idpDescriptor, spDescriptor);
        SingleLogoutService logoutService = SAMLUtil.getLogoutServiceForBinding(idpDescriptor, binding);

        logoutResponse.setID(generateID());
        logoutResponse.setIssuer(getIssuer(context.getLocalEntityId()));
        logoutResponse.setVersion(SAMLVersion.VERSION_20);
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setInResponseTo(context.getInboundSAMLMessageId());
        logoutResponse.setDestination(logoutService.getLocation());

        Status status = getStatus(statusCode, statusMessage);
        logoutResponse.setStatus(status);

        context.setCommunicationProfileId(getProfileIdentifier());
        context.setOutboundMessage(logoutResponse);
        context.setOutboundSAMLMessage(logoutResponse);
        context.setPeerEntityEndpoint(logoutService);

        context.setPeerEntityId(idpDescriptor.getID());
        context.setPeerEntityRoleMetadata(idpDescriptor);

        boolean signMessage = context.getPeerExtendedMetadata().isRequireLogoutResponseSigned();
        sendMessage(context, signMessage);

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

    protected NameID getNameID(SAMLMessageContext context, LogoutRequest request) throws DecryptionException {
        NameID id;
        if (request.getEncryptedID() != null) {
            Assert.notNull(context.getLocalDecrypter(), "Can't decrypt NameID, no decrypter is set in the context");
            id = (NameID) context.getLocalDecrypter().decrypt(request.getEncryptedID());
        } else {
            id = request.getNameID();
        }
        return id;
    }

    public void processLogoutResponse(SAMLMessageContext context) throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException {

        SAMLObject message = context.getInboundSAMLMessage();

        // Verify type
        if (!(message instanceof LogoutResponse)) {
            throw new SAMLException("Message is not of a LogoutResponse object type");
        }
        LogoutResponse response = (LogoutResponse) message;

        // Make sure request was authenticated if required, authentication is done as part of the binding processing
        if (!context.isInboundSAMLMessageAuthenticated() && context.getLocalExtendedMetadata().isRequireLogoutResponseSigned()) {
            throw new SAMLException("Logout Response object is required to be signed by the entity policy: " + context.getInboundSAMLMessageId());
        }

        // Verify issue time
        DateTime time = response.getIssueInstant();
        if (!isDateTimeSkewValid(getResponseSkew(), time)) {
            throw new SAMLException("Response issue time in LogoutResponse is either too old or with date in the future");
        }

        // Verify response to field if present, set request if correct
        // The inResponseTo field is optional, SAML 2.0 Core, 1542
        SAMLMessageStorage messageStorage = context.getMessageStorage();
        if (messageStorage != null && response.getInResponseTo() != null) {
            XMLObject xmlObject = messageStorage.retrieveMessage(response.getInResponseTo());
            if (xmlObject == null) {
                throw new SAMLException("InResponseToField in LogoutResponse doesn't correspond to sent message " + response.getInResponseTo());
            } else if (xmlObject instanceof LogoutRequest) {
                // Expected
            } else {
                throw new SAMLException("Sent request was of different type than the expected LogoutRequest " + response.getInResponseTo());
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
                        context.getInboundSAMLBinding().equals(service.getBinding())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new SAMLException("Destination in the LogoutResponse was not the expected value " + response.getDestination());
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
            log.debug("Single Logout was successful");
        } else if (StatusCode.PARTIAL_LOGOUT_URI.equals(statusCode)) {
            log.debug("Single Logout was partially successful");
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
