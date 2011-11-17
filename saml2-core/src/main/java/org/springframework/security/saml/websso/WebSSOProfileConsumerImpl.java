/* Copyright 2009 Vladimir Schäfer
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
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.util.Assert;

import javax.xml.namespace.QName;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

/**
 * Class is able to process Response objects returned from the IDP after SP initialized SSO or unsolicited
 * response from IDP. In case the response is correctly validated and no errors are found the SAMLCredential
 * is created.
 *
 * @author Vladimir Schäfer
 */
public class WebSSOProfileConsumerImpl extends AbstractProfileBase implements WebSSOProfileConsumer {

    private final static Logger log = LoggerFactory.getLogger(WebSSOProfileConsumerImpl.class);

    public WebSSOProfileConsumerImpl() {
    }

    public WebSSOProfileConsumerImpl(SAMLProcessor processor, MetadataManager manager) {
        super(processor, manager);
    }

    @Override
    public String getProfileIdentifier() {
        return SAMLConstants.SAML2_WEBSSO_PROFILE_URI;
    }

    /**
     * Maximum time between users authentication and processing of the AuthNResponse message.
     */
    private int maxAuthenticationAge = 7200;

    /**
     * The input context object must have set the properties related to the returned Response, which is validated
     * and in case no errors are found the SAMLCredential is returned.
     *
     * @param context context including response object
     * @return SAMLCredential with information about user
     * @throws SAMLException       in case the response is invalid
     * @throws org.opensaml.xml.security.SecurityException
     *                             in the signature on response can't be verified
     * @throws ValidationException in case the response structure is not conforming to the standard
     */
    public SAMLCredential processAuthenticationResponse(SAMLMessageContext context, SAMLMessageStorage protocolCache) throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException, DecryptionException {

        AuthnRequest request = null;
        SAMLObject message = context.getInboundSAMLMessage();

        // Verify type
        if (!(message instanceof Response)) {
            log.debug("Received response is not of a Response object type");
            throw new SAMLException("Error validating SAML response");
        }
        Response response = (Response) message;

        // Verify status
        if (!StatusCode.SUCCESS_URI.equals(response.getStatus().getStatusCode().getValue())) {
            String[] logMessage = new String[2];
            logMessage[0] = response.getStatus().getStatusCode().getValue();
            StatusMessage message1 = response.getStatus().getStatusMessage();
            if (message1 != null) {
                logMessage[1] = message1.getMessage();
            }
            log.debug("Received response has invalid status code", logMessage);
            throw new SAMLException("SAML status is not success code");
        }

        // Verify signature of the response if present
        if (response.getSignature() != null) {
            verifySignature(response.getSignature(), context.getPeerEntityId(), context.getLocalTrustEngine());
            context.setInboundSAMLMessageAuthenticated(true);
        }

        // Verify issue time
        DateTime time = response.getIssueInstant();
        if (!isDateTimeSkewValid(getResponseSkew(), time)) {
            log.debug("Response issue time is either too old or with date in the future, skew {}, time {}.", getResponseSkew(), time);
            throw new SAMLException("Error validating SAML response");
        }

        // Verify response to field if present, set request if correct
        if (response.getInResponseTo() != null) {
            XMLObject xmlObject = protocolCache.retrieveMessage(response.getInResponseTo());
            if (xmlObject == null) {
                log.debug("InResponseToField doesn't correspond to sent message", response.getInResponseTo());
                throw new SAMLException("Error validating SAML response");
            } else if (xmlObject instanceof AuthnRequest) {
                request = (AuthnRequest) xmlObject;
            } else {
                log.debug("Sent request was of different type then received response", response.getInResponseTo());
                throw new SAMLException("Error validating SAML response");
            }
        }

        // Verify that message was received at the expected endpoint
        verifyEndpoint(context.getLocalEntityEndpoint(), response.getDestination());

        // Verify endpoint requested in the original request
        if (request != null) {
            AssertionConsumerService assertionConsumerService = (AssertionConsumerService) context.getLocalEntityEndpoint();
            if (request.getAssertionConsumerServiceIndex() != null) {
                if (!request.getAssertionConsumerServiceIndex().equals(assertionConsumerService.getIndex())) {
                    log.info("SAML response was received at a different endpoint index than was requested");
                }
            } else {
                String requestedResponseURL = request.getAssertionConsumerServiceURL();
                String requestedBinding = request.getProtocolBinding();
                if (requestedResponseURL != null) {
                    String responseLocation;
                    if (assertionConsumerService.getResponseLocation() != null) {
                        responseLocation = assertionConsumerService.getResponseLocation();
                    } else {
                        responseLocation = assertionConsumerService.getLocation();
                    }
                    if (!requestedResponseURL.equals(responseLocation)) {
                        log.info("SAML response was received at a different endpoint URL {} than was requested {}", responseLocation, requestedResponseURL);
                    }
                }
                if (requestedBinding != null) {
                    if (!requestedBinding.equals(context.getInboundSAMLBinding())) {
                        log.info("SAML response was received using a different binding {} than was requested {}", context.getInboundSAMLBinding(), requestedBinding);
                    }
                }
            }
        }

        // Verify issuer
        if (response.getIssuer() != null) {
            Issuer issuer = response.getIssuer();
            verifyIssuer(issuer, context);
        }

        Assertion subjectAssertion = null;
        List<Attribute> attributes = new LinkedList<Attribute>();

        // Verify assertions
        List<Assertion> assertionList = response.getAssertions();
        List<EncryptedAssertion> encryptedAssertionList = response.getEncryptedAssertions();
        for (EncryptedAssertion ea : encryptedAssertionList) {
            try {
                Assert.notNull(context.getLocalDecrypter(), "Can't decrypt Assertion, no decrypter is set in the context");
                Assertion decryptedAssertion = context.getLocalDecrypter().decrypt(ea);
                assertionList.add(decryptedAssertion);
            } catch (DecryptionException e) {
                log.debug("Decryption of received assertion failed, assertion will be skipped", e);
            }
        }

        // Find the assertion to be used for session creation, other assertions are ignored
        for (Assertion a : assertionList) {

            // We're only interested in assertions with AuthnStatement
            if (a.getAuthnStatements().size() > 0) {
                try {
                    // Verify that the assertion is valid
                    verifyAssertion(a, request, context);
                } catch (AuthenticationException e) {
                    log.debug("Validation of received assertion failed, assertion will be skipped", e);
                    continue;
                } catch (SAMLRuntimeException e) {
                    log.debug("Validation of received assertion failed, assertion will be skipped", e);
                    continue;
                } catch (SAMLException e) {
                    log.debug("Validation of received assertion failed, assertion will be skipped", e);
                    continue;
                } catch (org.opensaml.xml.security.SecurityException e) {
                    log.debug("Validation of received assertion failed, assertion will be skipped", e);
                    continue;
                } catch (ValidationException e) {
                    log.debug("Validation of received assertion failed, assertion will be skipped", e);
                    continue;
                } catch (DecryptionException e) {
                    log.debug("Validation of received assertion failed, assertion will be skipped", e);
                    continue;
                }
            }

            subjectAssertion = a;

            // Process all attributes
            for (AttributeStatement attStatement : a.getAttributeStatements()) {
                for (Attribute att : attStatement.getAttributes()) {
                    attributes.add(att);
                }
                for (EncryptedAttribute att : attStatement.getEncryptedAttributes()) {
                    Assert.notNull(context.getLocalDecrypter(), "Can't decrypt Attribute, no decrypter is set in the context");
                    attributes.add(context.getLocalDecrypter().decrypt(att));
                }
            }

            break;

        }

        // Make sure that at least one storage contains authentication statement and subject with bearer confirmation
        if (subjectAssertion == null) {
            log.debug("Response doesn't any valid assertion which would pass subject validation");
            throw new SAMLException("Error validating SAML response");
        }

        NameID nameId = (NameID) context.getSubjectNameIdentifier();
        if (nameId == null) {
            throw new SAMLException("NameID element must be present as part of the Subject in the Response message, please enable it in the IDP configuration");
        }

        // Populate custom data, if any
        Serializable additionalData = processAdditionalData(context);

        // Create the credential
        return new SAMLCredential(nameId, subjectAssertion, context.getPeerEntityMetadata().getEntityID(), context.getRelayState(), attributes, context.getLocalEntityId(), additionalData);

    }

    /**
     * This is a hook method enabling subclasses to process additional data from the SAML exchange, like assertions with different confirmations
     * or additional attributes. The returned object is stored inside the SAMLCredential. Implementation is responsible for ensuring compliance
     * with the SAML specification. The method is called once all the other processing was finished and incoming message is deemed as valid.
     *
     * @param context context containing incoming message
     * @return object to store in the credential, null by default
     * @throws SAMLException in case processing fails
     */
    protected Serializable processAdditionalData(SAMLMessageContext context) throws SAMLException {
        return null;
    }

    protected void verifyAssertion(Assertion assertion, AuthnRequest request, SAMLMessageContext context) throws AuthenticationException, SAMLException, org.opensaml.xml.security.SecurityException, ValidationException, DecryptionException {

        // Verify storage time skew
        if (!isDateTimeSkewValid(getMaxAssertionTime(), assertion.getIssueInstant())) {
            log.debug("Assertion is too old to be used, value can be customized by setting maxAssertionTime value", assertion.getIssueInstant());
            throw new CredentialsExpiredException("Users authentication credential is too old to be used");
        }

        // Verify validity of storage
        // Advice is ignored, core 574
        verifyIssuer(assertion.getIssuer(), context);
        verifyAssertionSignature(assertion.getSignature(), context);

        // Check subject
        if (assertion.getSubject() != null) {
            verifySubject(assertion.getSubject(), request, context);
        } else {
            throw new SAMLException("Assertion without subject is discarded");
        }

        // Assertion with authentication statement must contain audience restriction
        if (assertion.getAuthnStatements().size() > 0) {
            verifyAssertionConditions(assertion.getConditions(), context, true);
            for (AuthnStatement statement : assertion.getAuthnStatements()) {
                if (request != null) {
                    verifyAuthenticationStatement(statement, request.getRequestedAuthnContext(), context);
                } else {
                    verifyAuthenticationStatement(statement, null, context);
                }
            }
        } else {
            verifyAssertionConditions(assertion.getConditions(), context, false);
        }

    }

    /**
     * Verifies validity of Subject element, only bearer confirmation is validated.
     *
     * @param subject subject to validate
     * @param request request
     * @param context context
     * @throws SAMLException       error validating the object
     * @throws DecryptionException in case the NameID can't be decrypted
     */
    protected void verifySubject(Subject subject, AuthnRequest request, SAMLMessageContext context) throws SAMLException, DecryptionException {

        for (SubjectConfirmation confirmation : subject.getSubjectConfirmations()) {

            if (SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())) {

                log.debug("Processing Bearer subject confirmation");
                SubjectConfirmationData data = confirmation.getSubjectConfirmationData();

                // Bearer must have confirmation 554
                if (data == null) {
                    log.debug("Bearer SubjectConfirmation invalidated by missing confirmation data");
                    continue;
                }

                // Not before forbidden by core 558
                if (data.getNotBefore() != null) {
                    log.debug("Bearer SubjectConfirmation invalidated by not before which is forbidden");
                    continue;
                }

                // Validate not on or after
                if (data.getNotOnOrAfter().isBeforeNow()) {
                    log.debug("Bearer SubjectConfirmation invalidated by notOnOrAfter");
                    continue;
                }

                // Validate in response to
                if (request != null) {
                    if (data.getInResponseTo() == null) {
                        log.debug("Bearer SubjectConfirmation invalidated by missing inResponseTo field");
                        continue;
                    } else {
                        if (!data.getInResponseTo().equals(request.getID())) {
                            log.debug("Bearer SubjectConfirmation invalidated by invalid in response to");
                            continue;
                        }
                    }
                }

                // Validate recipient
                if (data.getRecipient() == null) {
                    log.debug("Bearer SubjectConfirmation invalidated by missing recipient");
                    continue;
                } else {
                    try {
                        verifyEndpoint(context.getLocalEntityEndpoint(), data.getRecipient());
                    } catch (SAMLException e) {
                        log.debug("Bearer SubjectConfirmation invalidated by recipient assertion consumer URL, found {}", data.getRecipient());
                        continue;
                    }
                }

                // Was the subject confirmed by this confirmation data? If so let's store the subject in the context.
                NameID nameID;
                if (subject.getEncryptedID() != null) {
                    Assert.notNull(context.getLocalDecrypter(), "Can't decrypt NameID, no decrypter is set in the context");
                    nameID = (NameID) context.getLocalDecrypter().decrypt(subject.getEncryptedID());
                } else {
                    nameID = subject.getNameID();
                }
                context.setSubjectNameIdentifier(nameID);
                return;

            }

        }

        log.debug("Assertion invalidated by subject confirmation - can't be confirmed by the bearer method");
        throw new SAMLException("SAML Assertion is invalid");

    }

    /**
     * Verifies signature of the assertion. In case signature is not present and SP required signatures in metadata
     * the exception is thrown.
     *
     * @param signature signature to verify
     * @param context   context
     * @throws SAMLException       signature missing although required
     * @throws org.opensaml.xml.security.SecurityException
     *                             signature can't be validated
     * @throws ValidationException signature is malformed
     */
    protected void verifyAssertionSignature(Signature signature, SAMLMessageContext context) throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException {
        SPSSODescriptor roleMetadata = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
        boolean wantSigned = roleMetadata.getWantAssertionsSigned();
        if (signature != null) {
            verifySignature(signature, context.getPeerEntityMetadata().getEntityID(), context.getLocalTrustEngine());
        } else if (wantSigned) {
            log.debug("Assertion must be signed, but is not");
            throw new SAMLException("SAML Assertion is invalid");
        }
    }

    protected void verifyAssertionConditions(Conditions conditions, SAMLMessageContext context, boolean audienceRequired) throws SAMLException {

        // If no conditions are implied, storage is deemed valid
        if (conditions == null) {
            return;
        }

        if (conditions.getNotBefore() != null) {
            if (conditions.getNotBefore().isAfterNow()) {
                log.debug("Assertion is not yet valid, invalidated by condition notBefore", conditions.getNotBefore());
                throw new SAMLException("SAML response is not yet valid");
            }
        }
        if (conditions.getNotOnOrAfter() != null) {
            if (conditions.getNotOnOrAfter().isBeforeNow()) {
                log.debug("Assertion is no longer valid, invalidated by condition notOnOrAfter", conditions.getNotOnOrAfter());
                throw new SAMLException("SAML response is no longer valid");
            }
        }

        if (audienceRequired && conditions.getAudienceRestrictions().size() == 0) {
            log.debug("Assertion invalidated by missing Audience Restriction");
            throw new SAMLException("SAML response does not define Audience");
        }

        List<Condition> notUnderstoodConditions = new LinkedList<Condition>();

        for (Condition condition : conditions.getConditions()) {

            QName conditionQName = condition.getElementQName();

            if (conditionQName.equals(AudienceRestriction.DEFAULT_ELEMENT_NAME)) {

                audience:
                for (AudienceRestriction rest : conditions.getAudienceRestrictions()) {
                    if (rest.getAudiences().size() == 0) {
                        log.debug("No audit audience specified for the assertion");
                        throw new SAMLException("SAML response does not define Audience in AudienceRestriction");
                    }
                    for (Audience aud : rest.getAudiences()) {
                        if (context.getLocalEntityId().equals(aud.getAudienceURI())) {
                            continue audience;
                        }
                    }
                    log.debug("Our entity is not the intended audience of the assertion");
                    throw new SAMLException("SAML response is not intended for this Audience");
                }

            } else if (conditionQName.equals(OneTimeUse.DEFAULT_ELEMENT_NAME)) {

                log.debug("System cannot honor OneTimeUse condition of the SAML Assertion for WebSSO");
                throw new SAMLException("System cannot honor OneTimeUse condition of the SAML Assertion for WebSSO");

            } else if (conditionQName.equals(ProxyRestriction.DEFAULT_ELEMENT_NAME)) {

                ProxyRestriction restriction = (ProxyRestriction) condition;
                log.debug("Honoring ProxyRestriction with count {}, system does not issue assertions to 3rd parties", restriction.getProxyCount());

            } else {

                log.debug("Condition {} is not understood", condition);
                notUnderstoodConditions.add(condition);

            }

        }

        // Check not understood conditions
        verifyConditions(context, notUnderstoodConditions);

    }

    /**
     * Verifies conditions of the assertion which were are not understood. By default system fails in case any
     * non-understood condition is present.
     *
     * @param context    message context
     * @param conditions conditions which were not understood
     * @throws SAMLException in case conditions are not empty
     */
    protected void verifyConditions(SAMLMessageContext context, List<Condition> conditions) throws SAMLException {
        if (conditions != null && conditions.size() > 0) {
            log.debug("Assertion contain not understood conditions");
            throw new SAMLException("SAML response is not valid");
        }
    }

    /**
     * Verifies that authentication statement is valid. Checks the authInstant and sessionNotOnOrAfter fields.
     *
     * @param auth                  statement to check
     * @param requestedAuthnContext original requested context can be null for unsolicited messages or when no context was requested
     * @param context               message context
     * @throws AuthenticationException in case the statement is invalid
     */
    protected void verifyAuthenticationStatement(AuthnStatement auth, RequestedAuthnContext requestedAuthnContext, SAMLMessageContext context) throws AuthenticationException {

        // Validate that user wasn't authenticated too long time ago
        if (!isDateTimeSkewValid(getMaxAuthenticationAge(), auth.getAuthnInstant())) {
            log.debug("Authentication statement is too old to be used", auth.getAuthnInstant());
            throw new CredentialsExpiredException("Users authentication data is too old");
        }

        // Validate users session is still valid
        if (auth.getSessionNotOnOrAfter() != null && !(new DateTime()).isBefore(auth.getSessionNotOnOrAfter())) {
            log.debug("Authentication session is not valid anymore", auth.getSessionNotOnOrAfter());
            throw new CredentialsExpiredException("Users authentication is expired");
        }

        // Verify context
        verifyAuthnContext(requestedAuthnContext, auth.getAuthnContext(), context);

    }

    /**
     * Implementation is expected to verify that the requested authentication context corresponds with the received value.
     * Identity provider sending the context can be loaded from the SAMLContext.
     * <p/>
     * By default verification is done only for "exact" context. It is checked whether received context contains one of the requested
     * method.
     * <p/>
     * In case requestedAuthnContext is null no verification is done.
     * <p/>
     * Method can be reimplemented in subclasses.
     *
     * @param requestedAuthnContext context requested in the original request, null for unsolicited messages or when no context was required
     * @param receivedContext       context from the response message
     * @param context               saml context
     * @throws InsufficientAuthenticationException
     *          in case expected context doesn't correspond with the received value
     */
    protected void verifyAuthnContext(RequestedAuthnContext requestedAuthnContext, AuthnContext receivedContext, SAMLMessageContext context) throws InsufficientAuthenticationException {

        if (requestedAuthnContext != null && AuthnContextComparisonTypeEnumeration.EXACT.equals(requestedAuthnContext.getComparison())) {

            String classRef = null, declRef = null;

            if (receivedContext.getAuthnContextClassRef() != null) {
                classRef = receivedContext.getAuthnContextClassRef().getAuthnContextClassRef();
            }

            if (requestedAuthnContext.getAuthnContextClassRefs() != null) {
                for (AuthnContextClassRef classRefRequested : requestedAuthnContext.getAuthnContextClassRefs()) {
                    if (classRefRequested.getAuthnContextClassRef().equals(classRef)) {
                        return;
                    }
                }
            }

            if (receivedContext.getAuthnContextDeclRef() != null) {
                declRef = receivedContext.getAuthnContextDeclRef().getAuthnContextDeclRef();
            }

            if (requestedAuthnContext.getAuthnContextDeclRefs() != null) {
                for (AuthnContextDeclRef declRefRequested : requestedAuthnContext.getAuthnContextDeclRefs()) {
                    if (declRefRequested.getAuthnContextDeclRef().equals(declRef)) {
                        return;
                    }
                }
            }

            throw new InsufficientAuthenticationException("Response doesn't contain any of the requested authentication context class or declaration references");

        }

    }

    /**
     * Maximum time between authentication of user and processing of an authentication statement.
     *
     * @return max authentication age, defaults to 7200
     */
    public int getMaxAuthenticationAge() {
        return maxAuthenticationAge;
    }

    /**
     * Sets maximum time between users authentication and processing of an authentication statement.
     *
     * @param maxAuthenticationAge authentication age
     */
    public void setMaxAuthenticationAge(int maxAuthenticationAge) {
        this.maxAuthenticationAge = maxAuthenticationAge;
    }

}