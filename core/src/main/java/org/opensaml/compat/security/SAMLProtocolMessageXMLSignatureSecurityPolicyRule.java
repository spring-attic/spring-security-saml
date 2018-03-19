/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat.security;

import org.opensaml.compat.BackwardsCompatibleMessageContext;
import org.opensaml.compat.validation.ValidationException;
import org.opensaml.compat.validation.Validator;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * SAML security policy rule which validates the signature (if present) on the {@link SAMLObject} which represents the
 * SAML protocol message being processed.
 *
 * <p>
 * If the message is not an instance of {@link SignableSAMLObject}, then no processing is performed. If signature
 * validation is successful, and the SAML message context issuer was not previously authenticated, then the context's
 * issuer authentication state will be set to <code>true</code>.
 * </p>
 *
 * <p>
 * If an optional {@link Validator} for {@link Signature} objects is supplied, this validator will be used to validate
 * the XML Signature element prior to the actual cryptographic validation of the signature. This might for example be
 * used to enforce certain signature profile requirements or to detect signatures upon which it would be unsafe to
 * attempt cryptographic processing. When using the single argument constructuor form, the validator will default to
 * {@link SAMLSignatureProfileValidator}.
 * </p>
 */
public class SAMLProtocolMessageXMLSignatureSecurityPolicyRule extends BaseSAMLXMLSignatureSecurityPolicyRule {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(SAMLProtocolMessageXMLSignatureSecurityPolicyRule.class);

    /** Validator for XML Signature instances. */
    private Validator<Signature> sigValidator;

    /**
     * Constructor.
     *
     * Signature pre-validator defaults to {@link SAMLSignatureProfileValidator}.
     *
     * @param engine Trust engine used to verify the signature
     */
    public SAMLProtocolMessageXMLSignatureSecurityPolicyRule(TrustEngine<Signature> engine) {
        super(engine);
        sigValidator = new Validator<Signature>() {
            @Override
            public void validate(Signature xmlObject) throws ValidationException {
                try {
                    new SAMLSignatureProfileValidator().validate(xmlObject);
                } catch (SignatureException e) {
                    throw new ValidationException(e);
                }
            }
        };
    }

    /**
     * Constructor.
     *
     * @param engine Trust engine used to verify the signature
     * @param signatureValidator optional pre-validator used to validate Signature elements prior to the actual
     *            cryptographic validation operation
     */
    public SAMLProtocolMessageXMLSignatureSecurityPolicyRule(TrustEngine<Signature> engine,
            Validator<Signature> signatureValidator) {
        super(engine);
        sigValidator = signatureValidator;
    }

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException, SecurityException {
        if (!(messageContext instanceof BackwardsCompatibleMessageContext)) {
            log.debug("Invalid message context type, this policy rule only supports BackwardsCompatibleMessageContext");
            return;
        }

        BackwardsCompatibleMessageContext samlMsgCtx = (BackwardsCompatibleMessageContext) messageContext;

        SAMLObject samlMsg = samlMsgCtx.getInboundSAMLMessage();
        if (!(samlMsg instanceof SignableSAMLObject)) {
            log.debug("Extracted SAML message was not a SignableSAMLObject, can not process signature");
            return;
        }
        SignableSAMLObject signableObject = (SignableSAMLObject) samlMsg;
        if (!signableObject.isSigned()) {
            log.info("SAML protocol message was not signed, skipping XML signature processing");
            return;
        }
        Signature signature = signableObject.getSignature();

        performPreValidation(signature);

        doEvaluate(signature, signableObject, samlMsgCtx);
    }

    /**
     * Perform cryptographic validation and trust evaluation on the Signature token using the configured Signature trust
     * engine.
     *
     * @param signature the signature which is being evaluated
     * @param signableObject the signable object which containinboundSAMLMessageAuthenticateded the signature
     * @param samlMsgCtx the SAML message context being processed
     * @throws SecurityPolicyException thrown if the signature fails validation
     */
    protected void doEvaluate(Signature signature, SignableSAMLObject signableObject, BackwardsCompatibleMessageContext samlMsgCtx)
        throws SecurityPolicyException, SecurityException {

        String contextIssuer = samlMsgCtx.getInboundMessageIssuer();
        if (contextIssuer != null) {
            String msgType = signableObject.getElementQName().toString();
            log.debug("Attempting to verify signature on signed SAML protocol message using context issuer message type: {}",
                            msgType);

            if (evaluate(signature, contextIssuer, samlMsgCtx)) {
                log.info("Validation of protocol message signature succeeded, message type: {}", msgType);
                if (!samlMsgCtx.isInboundSAMLMessageAuthenticated()) {
                    log.debug("Authentication via protocol message signature succeeded for context issuer entity ID {}",
                            contextIssuer);
                    samlMsgCtx.setInboundSAMLMessageAuthenticated(true);
                }
            } else {
                log.debug("Validation of protocol message signature failed for context issuer '" + contextIssuer
                        + "', message type: " + msgType);
                throw new SecurityPolicyException("Validation of protocol message signature failed");
            }
        } else {
            log.debug("Context issuer unavailable, can not attempt SAML protocol message signature validation");
            throw new SecurityPolicyException("Context issuer unavailable, can not validate signature");
        }
    }

    /**
     * Get the validator used to perform pre-validation on Signature tokens.
     *
     * @return the configured Signature validator, or null
     */
    protected Validator<Signature> getSignaturePrevalidator() {
        return sigValidator;
    }

    /**
     * Perform pre-validation on the Signature token.
     *
     * @param signature the signature to evaluate
     * @throws SecurityPolicyException thrown if the signature element fails pre-validation
     */
    protected void performPreValidation(Signature signature) throws SecurityPolicyException {
        if (getSignaturePrevalidator() != null) {
            try {
                getSignaturePrevalidator().validate(signature);
            } catch (ValidationException e) {
                log.debug("Protocol message signature failed signature pre-validation", e);
                throw new SecurityPolicyException("Protocol message signature failed signature pre-validation", e);
            }
        }
    }
}