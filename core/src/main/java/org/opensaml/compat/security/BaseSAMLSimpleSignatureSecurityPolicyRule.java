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

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.MetadataCriteria;
import org.opensaml.compat.UsageCriteria;
import org.opensaml.compat.transport.http.HttpServletRequestAdapter;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Base class for security rules which verify simple "blob" signatures computed over some components of a request.
 */
public abstract class BaseSAMLSimpleSignatureSecurityPolicyRule implements SecurityPolicyRule {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(BaseSAMLSimpleSignatureSecurityPolicyRule.class);

    /** Signature trust engine used to validate raw signatures. */
    private SignatureTrustEngine trustEngine;

    /**
     * Constructor.
     *
     * @param engine the signature trust engine to use for signature validataion
     */
    protected BaseSAMLSimpleSignatureSecurityPolicyRule(SignatureTrustEngine engine) {
        trustEngine = engine;
    }

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException, SecurityException {
        log.debug("Evaluating simple signature rule of type: {}", getClass().getName());
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.debug("Invalid message context type, this policy rule only supports SAMLMessageContext");
            return;
        }

        if (!(((SAMLMessageContext)messageContext).getInboundMessageTransport() instanceof HttpServletRequestAdapter)) {
            log.debug("Invalid inbound message transport type, this rule only supports HttpServletRequestAdapter");
            return;
        }

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;
        HttpServletRequestAdapter requestAdapter = (HttpServletRequestAdapter) ((SAMLMessageContext)messageContext)
                .getInboundMessageTransport();
        HttpServletRequest request = requestAdapter.getWrappedRequest();

        if (!ruleHandles(request, samlMsgCtx)) {
            log.debug("Rule can not handle this request, skipping processing");
            return;
        }

        byte[] signature = getSignature(request);
        if (signature == null || signature.length == 0) {
            log.debug("HTTP request was not signed via simple signature mechanism, skipping");
            return;
        }

        String sigAlg = getSignatureAlgorithm(request);
        if (DataTypeHelper.isEmpty(sigAlg)) {
            log.warn("Signature algorithm could not be extracted from request, can not validate simple signature");
            return;
        }

        byte[] signedContent = getSignedContent(request);
        if (signedContent == null || signedContent.length == 0) {
            log.warn("Signed content could not be extracted from HTTP request, can not validate");
            return;
        }

        doEvaluate(signature, signedContent, sigAlg, request, samlMsgCtx);
    }

    /**
     * Evaluate the simple signature based on information in the request and/or message context.
     *
     * @param signature the signature value
     * @param signedContent the content that was signed
     * @param algorithmURI the signature algorithm URI which was used to sign the content
     * @param request the HTTP servlet request being processed
     * @param samlMsgCtx the SAML message context being processed
     *
     * @throws SecurityPolicyException thrown if there are errors during the signature validation process
     *
     */
    private void doEvaluate(byte[] signature, byte[] signedContent, String algorithmURI, HttpServletRequest request,
            SAMLMessageContext samlMsgCtx) throws SecurityPolicyException, SecurityException {

        List<Credential> candidateCredentials = getRequestCredentials(request, samlMsgCtx);

        String contextIssuer = samlMsgCtx.getInboundMessageIssuer();

        if (contextIssuer != null) {
            log.debug("Attempting to validate SAML protocol message simple signature using context issuer: {}",
                    contextIssuer);
            CriteriaSet criteriaSet = buildCriteriaSet(contextIssuer, samlMsgCtx);
            if (validateSignature(signature, signedContent, algorithmURI, criteriaSet, candidateCredentials)) {
                log.info("Validation of request simple signature succeeded");
                if (!samlMsgCtx.isInboundSAMLMessageAuthenticated()) {
                    log.info("Authentication via request simple signature succeeded for context issuer entity ID {}",
                            contextIssuer);
                    samlMsgCtx.setInboundSAMLMessageAuthenticated(true);
                }
                return;
            } else {
                log.warn("Validation of request simple signature failed for context issuer: {}", contextIssuer);
                throw new SecurityPolicyException("Validation of request simple signature failed for context issuer");
            }
        }

        String derivedIssuer = deriveSignerEntityID(samlMsgCtx);
        if (derivedIssuer != null) {
            log.debug("Attempting to validate SAML protocol message simple signature using derived issuer: {}",
                    derivedIssuer);
            CriteriaSet criteriaSet = buildCriteriaSet(derivedIssuer, samlMsgCtx);
            if (validateSignature(signature, signedContent, algorithmURI, criteriaSet, candidateCredentials)) {
                log.info("Validation of request simple signature succeeded");
                if (!samlMsgCtx.isInboundSAMLMessageAuthenticated()) {
                    log.info("Authentication via request simple signature succeeded for derived issuer {}",
                            derivedIssuer);
                    samlMsgCtx.setInboundMessageIssuer(derivedIssuer);
                    samlMsgCtx.setInboundSAMLMessageAuthenticated(true);
                }
                return;
            } else {
                log.warn("Validation of request simple signature failed for derived issuer: {}", derivedIssuer);
                throw new SecurityPolicyException("Validation of request simple signature failed for derived issuer");
            }
        }

        log.warn("Neither context nor derived issuer available, can not attempt SAML simple signature validation");
        throw new SecurityPolicyException("No message issuer available, can not attempt simple signature validation");
    }

    /**
     * Validate the simple signature.
     *
     * @param signature the signature value
     * @param signedContent the content that was signed
     * @param algorithmURI the signature algorithm URI which was used to sign the content
     * @param criteriaSet criteria used to describe and/or resolve the information which serves as the basis for trust
     *            evaluation
     * @param candidateCredentials the request-derived candidate credential(s) containing the validation key for the
     *            signature (optional)
     * @return true if signature can be verified successfully, false otherwise
     *
     * @throws SecurityPolicyException thrown if there are errors during the signature validation process
     *
     */
    protected boolean validateSignature(byte[] signature, byte[] signedContent, String algorithmURI,
            CriteriaSet criteriaSet, List<Credential> candidateCredentials)
        throws SecurityPolicyException, SecurityException {

        SignatureTrustEngine engine = getTrustEngine();

        // Some bindings allow candidate signing credentials to be supplied (e.g. via ds:KeyInfo), some do not.
        // So have 2 slightly different cases.
        try {
            if (candidateCredentials == null || candidateCredentials.isEmpty()) {
                if (engine.validate(signature, signedContent, algorithmURI, criteriaSet, null)) {
                    log.debug("Simple signature validation (with no request-derived credentials) was successful");
                    return true;
                } else {
                    log.warn("Simple signature validation (with no request-derived credentials) failed");
                    return false;
                }
            } else {
                for (Credential cred : candidateCredentials) {
                    if (engine.validate(signature, signedContent, algorithmURI, criteriaSet, cred)) {
                        log.debug("Simple signature validation succeeded with a request-derived credential");
                        return true;
                    }
                }
                log.warn("Signature validation using request-derived credentials failed");
                return false;
            }
        } catch (SecurityException e) {
            log.warn("There was an error evaluating the request's simple signature using the trust engine", e);
            throw new SecurityPolicyException("Error during trust engine evaluation of the simple signature", e);
        }
    }

    /**
     * Extract any candidate validation credentials from the request and/or message context.
     *
     * Some bindings allow validataion keys for the simple signature to be supplied, and others do not.
     *
     * @param request the HTTP servlet request being processed
     * @param samlContext the SAML message context being processed
     * @return a list of candidate validation credentials in the request, or null if none were present
     * @throws SecurityPolicyException thrown if there is an error during request processing
     */
    protected List<Credential> getRequestCredentials(HttpServletRequest request, SAMLMessageContext samlContext)
            throws SecurityPolicyException {
        // This will be specific to the binding and message types, so no default.
        return null;
    }

    /**
     * Gets the engine used to validate the signature.
     *
     * @return engine engine used to validate the signature
     */
    protected SignatureTrustEngine getTrustEngine() {
        return trustEngine;
    }

    /**
     * Extract the signature value from the request, in the form suitable for input into
     * {@link SignatureTrustEngine#validate(byte[], byte[], String, CriteriaSet, Credential)}.
     *
     * Defaults to the Base64-decoded value of the HTTP request parameter named <code>Signature</code>.
     *
     * @param request the HTTP servlet request
     * @return the signature value
     * @throws SecurityPolicyException thrown if there is an error during request processing
     */
    protected byte[] getSignature(HttpServletRequest request) throws SecurityPolicyException {
        String signature = request.getParameter("Signature");
        if (DataTypeHelper.isEmpty(signature)) {
            return null;
        }
        return Base64.decode(signature.getBytes());
    }

    /**
     * Extract the signature algorithm URI value from the request.
     *
     * Defaults to the HTTP request parameter named <code>SigAlg</code>.
     *
     * @param request the HTTP servlet request
     * @return the signature algorithm URI value
     * @throws SecurityPolicyException thrown if there is an error during request processing
     */
    protected String getSignatureAlgorithm(HttpServletRequest request) throws SecurityPolicyException {
        return request.getParameter("SigAlg");
    }

    /**
     * Derive the signer's entity ID from the message context.
     *
     * This is implementation-specific and there is no default. This is primarily an extension point for subclasses.
     *
     * @param samlContext the SAML message context being processed
     * @return the signer's derived entity ID
     * @throws SecurityPolicyException thrown if there is an error during request processing
     */
    protected String deriveSignerEntityID(SAMLMessageContext samlContext) throws SecurityPolicyException {
        // No default
        return null;
    }

    /**
     * Build a criteria set suitable for input to the trust engine.
     *
     * @param entityID the candidate issuer entity ID which is being evaluated
     * @param samlContext the message context which is being evaluated
     * @return a newly constructly set of criteria suitable for the configured trust engine
     * @throws SecurityPolicyException thrown if criteria set can not be constructed
     */
    protected CriteriaSet buildCriteriaSet(String entityID, SAMLMessageContext samlContext)
            throws SecurityPolicyException {

        CriteriaSet criteriaSet = new CriteriaSet();
        if (!DataTypeHelper.isEmpty(entityID)) {
            criteriaSet.add(new EntityIdCriterion(entityID));
        }

        MetadataCriteria mdCriteria = new MetadataCriteria(samlContext.getPeerEntityRole(), samlContext
                .getInboundSAMLProtocol());
        criteriaSet.add(mdCriteria);

        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

        return criteriaSet;
    }

    /**
     * Get the content over which to validate the signature, in the form suitable for input into
     * {@link SignatureTrustEngine#validate(byte[], byte[], String, CriteriaSet, Credential)}.
     *
     * @param request the HTTP servlet request being processed
     * @return the signed content extracted from the request, in the format suitable for input to the trust engine.
     * @throws SecurityPolicyException thrown if there is an error during request processing
     */
    protected abstract byte[] getSignedContent(HttpServletRequest request) throws SecurityPolicyException;

    /**
     * Determine whether the rule should handle the request, based on the unwrapped HTTP servlet request and/or message
     * context.
     *
     * @param request the HTTP servlet request being processed
     * @param samlMsgCtx the SAML message context being processed
     * @return true if the rule should attempt to process the request, otherwise false
     * @throws SecurityPolicyException thrown if there is an error during request processing
     */
    protected abstract boolean ruleHandles(HttpServletRequest request, SAMLMessageContext samlMsgCtx)
            throws SecurityPolicyException;

}
