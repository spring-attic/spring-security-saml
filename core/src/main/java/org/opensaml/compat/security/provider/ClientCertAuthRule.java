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

package org.opensaml.compat.security.provider;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.compat.BackwardsCompatibleMessageContext;
import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.UsageCriteria;
import org.opensaml.compat.X509Util;
import org.opensaml.compat.security.SecurityPolicyException;
import org.opensaml.compat.transport.InTransport;
import org.opensaml.compat.transport.Transport;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Base64;

/**
 * Policy rule that checks if the client cert used to authenticate the request is valid and trusted.
 *
 * <p>
 * This rule is only evaluated if the message context contains a peer {@link X509Credential} as returned from the
 * inbound message context's inbound message transport {@link Transport#getPeerCredential()}.
 * </p>
 *
 * <p>
 * The entity ID used to perform trust evaluation of the X509 credential is first retrieved via
 * {@link #getCertificatePresenterEntityID(MessageContext)}. If this value is non-null, trust evaluation proceeds on
 * that basis. If trust evaluation using this entity ID is successful, the message context's inbound transport
 * authentication state will be set to <code>true</code> and processing is terminated. If unsuccessful, a
 * {@link SecurityPolicyException} is thrown.
 * </p>
 *
 * <p>
 * If a non-null value was available from {@link #getCertificatePresenterEntityID(MessageContext)}, then rule evaluation
 * will be attempted as described in {@link #evaluateCertificateNameDerivedPresenters(X509Credential, MessageContext)},
 * based on the currently configured certificate name evaluation options. If this method returns a non-null certificate
 * presenter entity ID, it will be set on the message context by calling
 * {@link #setAuthenticatedCertificatePresenterEntityID(MessageContext, String)} The message context's inbound transport
 * authentication state will be set to <code>true</code> via
 * {@link InTransport#setAuthenticated(boolean)}. Rule processing is then terminated. If the
 * method returns null, the client certificate presenter entity ID and inbound transport authentication state will
 * remain unmodified and rule processing continues.
 * </p>
 *
 * <p>
 * Finally rule evaluation will proceed as described in
 * {@link #evaluateDerivedPresenters(X509Credential, MessageContext)}. This is primarily an extension point by which
 * subclasses may implement specific custom logic. If this method returns a non-null client certificate presenter entity
 * ID, it will be set via {@link #setAuthenticatedCertificatePresenterEntityID(MessageContext, String)}, the message
 * context's inbound transport authentication state will be set to <code>true</code> and rule processing is terminated.
 * If the method returns null, the client certificate presenter entity ID and transport authentication state will remain
 * unmodified.
 * </p>
 */
public class ClientCertAuthRule extends BaseTrustEngineRule<X509Credential> {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(ClientCertAuthRule.class);

    /** Options for derving client cert presenter entity ID's from an X.509 certificate. */
    private CertificateNameOptions certNameOptions;

    /**
     * Constructor.
     *
     * @param engine Trust engine used to verify the request X509Credential
     * @param nameOptions options for deriving certificate presenter entity ID's from an X.509 certificate
     *
     */
    public ClientCertAuthRule(TrustEngine<X509Credential> engine, CertificateNameOptions nameOptions) {
        super(engine);
        certNameOptions = nameOptions;
    }

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException, SecurityException {

        Credential peerCredential = ((BackwardsCompatibleMessageContext)messageContext).getInboundMessageTransport().getPeerCredential();

        if (peerCredential == null) {
            log.info("Inbound message transport did not contain a peer credential, "
                    + "skipping client certificate authentication");
            return;
        }
        if (!(peerCredential instanceof X509Credential)) {
            log.info("Inbound message transport did not contain an X509Credential, "
                    + "skipping client certificate authentication");
            return;
        }

        X509Credential requestCredential = (X509Credential) peerCredential;
        if (log.isDebugEnabled()) {
            try {
                log.debug("Attempting to authenticate inbound connection that presented the certificate:");
                log.debug(new String(Base64.encode(requestCredential.getEntityCertificate().getEncoded())));
            } catch (CertificateEncodingException e) {
                // do nothing
            }
        }
        doEvaluate(requestCredential, messageContext);
    }

    /**
     * Get the currently configured certificate name options.
     *
     * @return the certificate name options
     */
    protected CertificateNameOptions getCertificateNameOptions() {
        return certNameOptions;
    }

    /**
     * Evaluate the request credential.
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @throws SecurityPolicyException thrown if a certificate presenter entity ID available from the message context
     *             and the client certificate token can not be establishd as trusted on that basis, or if there is error
     *             during evaluation processing
     */
    protected void doEvaluate(X509Credential requestCredential, MessageContext messageContext)
        throws SecurityPolicyException, SecurityException {

        String presenterEntityID = getCertificatePresenterEntityID(messageContext);

        if (presenterEntityID != null) {
            log.debug("Attempting client certificate authentication using context presenter entity ID: {}",
                    presenterEntityID);
            if (evaluate(requestCredential, presenterEntityID, messageContext)) {
                log.info("Authentication via client certificate succeeded for context presenter entity ID: {}",
                        presenterEntityID);
                ((BackwardsCompatibleMessageContext)messageContext).getInboundMessageTransport().setAuthenticated(true);
            } else {
                log.error("Authentication via client certificate failed for context presenter entity ID {}",
                        presenterEntityID);
                throw new SecurityPolicyException(
                        "Client certificate authentication failed for context presenter entity ID");
            }
            return;
        }

        String derivedPresenter = evaluateCertificateNameDerivedPresenters(requestCredential, messageContext);
        if (derivedPresenter != null) {
            log.info("Authentication via client certificate succeeded for certificate-derived presenter entity ID {}",
                    derivedPresenter);
            setAuthenticatedCertificatePresenterEntityID(messageContext, derivedPresenter);
            ((BackwardsCompatibleMessageContext)messageContext).getInboundMessageTransport().setAuthenticated(true);
            return;
        }

        derivedPresenter = evaluateDerivedPresenters(requestCredential, messageContext);
        if (derivedPresenter != null) {
            log.info("Authentication via client certificate succeeded for derived presenter entity ID {}",
                    derivedPresenter);
            setAuthenticatedCertificatePresenterEntityID(messageContext, derivedPresenter);
            ((BackwardsCompatibleMessageContext)messageContext).getInboundMessageTransport().setAuthenticated(true);
            return;
        }
    }

    /**
     * Get the entity ID of the presenter of the client TLS certificate, as will be used for trust evaluation purposes.
     *
     * <p>
     * The default behavior is to return the value of {@link BackwardsCompatibleMessageContext#getInboundMessageIssuer()}. Subclasses may
     * override to implement different logic.
     * </p>
     *
     * @param messageContext the current message context
     * @return the entity ID of the client TLS certificate presenter
     */
    protected String getCertificatePresenterEntityID(MessageContext messageContext) {
        return ((BackwardsCompatibleMessageContext)messageContext).getInboundMessageIssuer();
    }

    /**
     * Store the sucessfully authenticated derived entity ID of the certificate presenter in the message context.
     *
     * <p>
     * The default behavior is to set the value by calling {@link BackwardsCompatibleMessageContext#setInboundMessageIssuer(String)}.
     * Subclasses may override to implement different logic.
     * </p>
     *
     * @param messageContext the current message context
     * @param entityID the successfully authenticated derived entity ID of the client TLS certificate presenter
     */
    protected void setAuthenticatedCertificatePresenterEntityID(MessageContext messageContext, String entityID) {
        ((BackwardsCompatibleMessageContext)messageContext).setInboundMessageIssuer(entityID);
    }

    /** {@inheritDoc} */
    protected CriteriaSet buildCriteriaSet(String entityID, MessageContext messageContext)
            throws SecurityPolicyException {

        CriteriaSet criteriaSet = new CriteriaSet();
        if (!DataTypeHelper.isEmpty(entityID)) {
            criteriaSet.add(new EntityIdCriterion(entityID));
        }

        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

        return criteriaSet;
    }

    /**
     * Evaluate any candidate presenter entity ID's which may be derived from the credential or other message context
     * information.
     *
     * <p>
     * This serves primarily as an extension point for subclasses to implement application-specific logic.
     * </p>
     *
     * <p>
     * If multiple derived candidate entity ID's would satisfy the trust engine criteria, the choice of which one to
     * return as the canonical presenter entity ID value is implementation-specific.
     * </p>
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     * @deprecated Use {@link #evaluateDerivedPresenters(X509Credential,MessageContext)} instead
     */
    protected String evaluateDerivedIssuers(X509Credential requestCredential, MessageContext messageContext)
            throws SecurityPolicyException {
        return evaluateDerivedPresenters(requestCredential, messageContext);
    }

    /**
     * Evaluate any candidate presenter entity ID's which may be derived from the credential or other message context
     * information.
     *
     * <p>
     * This serves primarily as an extension point for subclasses to implement application-specific logic.
     * </p>
     *
     * <p>
     * If multiple derived candidate entity ID's would satisfy the trust engine criteria, the choice of which one to
     * return as the canonical presenter entity ID value is implementation-specific.
     * </p>
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     */
    protected String evaluateDerivedPresenters(X509Credential requestCredential, MessageContext messageContext)
            throws SecurityPolicyException {

        return null;
    }

    /**
     * Evaluate candidate presenter entity ID's which may be derived from the request credential's entity certificate
     * according to the options supplied via {@link CertificateNameOptions}.
     *
     * <p>
     * Configured certificate name types are derived as candidate presenter entity ID's and processed in the following
     * order:
     * <ol>
     * <li>The certificate subject DN string as serialized by the X500DNHandler obtained via
     * {@link CertificateNameOptions#getX500DNHandler()} and using the output format indicated by
     * {@link CertificateNameOptions#getX500SubjectDNFormat()}.</li>
     * <li>Subject alternative names of the types configured via {@link CertificateNameOptions#getSubjectAltNames()}.
     * Note that this is a LinkedHashSet, so the order of evaluation is the order of insertion.</li>
     * <li>The first common name (CN) value appearing in the certificate subject DN.</li>
     * </ol>
     * </p>
     *
     * <p>
     * The first one of the above which is successfully evaluated by the trust engine using criteria built from
     * {@link BaseTrustEngineRule#buildCriteriaSet(String, MessageContext)} will be returned.
     * </p>
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a certificate presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     * @deprecated Use {@link #evaluateCertificateNameDerivedPresenters(X509Credential,MessageContext)} instead
     */
    protected String evaluateCertificateNameDerivedIssuers(X509Credential requestCredential,
            MessageContext messageContext) throws SecurityPolicyException, SecurityException {
        return evaluateCertificateNameDerivedPresenters(requestCredential, messageContext);
    }

    /**
     * Evaluate candidate presenter entity ID's which may be derived from the request credential's entity certificate
     * according to the options supplied via {@link CertificateNameOptions}.
     *
     * <p>
     * Configured certificate name types are derived as candidate presenter entity ID's and processed in the following
     * order:
     * <ol>
     * <li>The certificate subject DN string as serialized by the X500DNHandler obtained via
     * {@link CertificateNameOptions#getX500DNHandler()} and using the output format indicated by
     * {@link CertificateNameOptions#getX500SubjectDNFormat()}.</li>
     * <li>Subject alternative names of the types configured via {@link CertificateNameOptions#getSubjectAltNames()}.
     * Note that this is a LinkedHashSet, so the order of evaluation is the order of insertion.</li>
     * <li>The first common name (CN) value appearing in the certificate subject DN.</li>
     * </ol>
     * </p>
     *
     * <p>
     * The first one of the above which is successfully evaluated by the trust engine using criteria built from
     * {@link BaseTrustEngineRule#buildCriteriaSet(String, MessageContext)} will be returned.
     * </p>
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a certificate presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     */
    protected String evaluateCertificateNameDerivedPresenters(X509Credential requestCredential,
            MessageContext messageContext) throws SecurityPolicyException, SecurityException {

        String candidatePresenter = null;

        if (certNameOptions.evaluateSubjectDN()) {
            candidatePresenter = evaluateSubjectDN(requestCredential, messageContext);
            if (candidatePresenter != null) {
                return candidatePresenter;
            }
        }

        if (!certNameOptions.getSubjectAltNames().isEmpty()) {
            candidatePresenter = evaluateSubjectAltNames(requestCredential, messageContext);
            if (candidatePresenter != null) {
                return candidatePresenter;
            }
        }

        if (certNameOptions.evaluateSubjectCommonName()) {
            candidatePresenter = evaluateSubjectCommonName(requestCredential, messageContext);
            if (candidatePresenter != null) {
                return candidatePresenter;
            }
        }

        return null;
    }

    /**MessageContext
     * Evaluate the presenter entity ID as derived from the cert subject common name (CN).
     *
     * Only the first CN value from the subject DN is evaluated.
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     */
    protected String evaluateSubjectCommonName(X509Credential requestCredential, MessageContext messageContext)
        throws SecurityPolicyException, SecurityException {

        log.debug("Evaluating client cert by deriving presenter as cert CN");
        X509Certificate certificate = requestCredential.getEntityCertificate();
        String candidatePresenter = getCommonName(certificate);
        if (candidatePresenter != null) {
            if (evaluate(requestCredential, candidatePresenter, messageContext)) {
                log.info("Authentication succeeded for presenter entity ID derived from CN {}", candidatePresenter);
                return candidatePresenter;
            }
        }
        return null;
    }

    /**
     * Evaluate the presenter entity ID as derived from the cert subject DN.
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     */
    protected String evaluateSubjectDN(X509Credential requestCredential, MessageContext messageContext)
        throws SecurityPolicyException, SecurityException {

        log.debug("Evaluating client cert by deriving presenter as cert subject DN");
        X509Certificate certificate = requestCredential.getEntityCertificate();
        String candidatePresenter = getSubjectName(certificate);
        if (candidatePresenter != null) {
            if (evaluate(requestCredential, candidatePresenter, messageContext)) {
                log.info("Authentication succeeded for presenter entity ID derived from subject DN {}",
                        candidatePresenter);
                return candidatePresenter;
            }
        }
        return null;
    }

    /**
     * Evaluate the presenter entity ID as derived from the cert subject alternative names specified by types enumerated
     * in {@link CertificateNameOptions#getSubjectAltNames()}.
     *
     * @param requestCredential the X509Credential derived from the request
     * @param messageContext the message context being evaluated
     * @return a presenter entity ID which was successfully evaluated by the trust engine
     * @throws SecurityPolicyException thrown if there is error during processing
     */
    protected String evaluateSubjectAltNames(X509Credential requestCredential, MessageContext messageContext)
        throws SecurityPolicyException, SecurityException {

        log.debug("Evaluating client cert by deriving presenter from subject alt names");
        X509Certificate certificate = requestCredential.getEntityCertificate();
        for (Integer altNameType : certNameOptions.getSubjectAltNames()) {
            log.debug("Evaluating alt names of type: {}", altNameType.toString());
            List<String> altNames = getAltNames(certificate, altNameType);
            for (String altName : altNames) {
                if (evaluate(requestCredential, altName, messageContext)) {
                    log.info("Authentication succeeded for presenter entity ID derived from subject alt name {}",
                            altName);
                    return altName;
                }
            }
        }
        return null;
    }

    /**
     * Get the first common name (CN) value from the subject DN of the specified certificate.
     *
     * @param cert the certificate being processed
     * @return the first CN value, or null if there are none
     */
    protected String getCommonName(X509Certificate cert) {
        List<String> names = X509Util.getCommonNames(cert.getSubjectX500Principal());
        if (names != null && !names.isEmpty()) {
            String name = names.get(0);
            log.debug("Extracted common name from certificate: {}", name);
            return name;
        }
        return null;
    }

    /**
     * Get subject name from a certificate, using the currently configured X500DNHandler and subject DN output format.
     *
     * @param cert the certificate being processed
     * @return the subject name
     */
    protected String getSubjectName(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        String name = null;
        if (!DataTypeHelper.isEmpty(certNameOptions.getX500SubjectDNFormat())) {
            name = certNameOptions.getX500DNHandler().getName(cert.getSubjectX500Principal(),
                    certNameOptions.getX500SubjectDNFormat());
        } else {
            name = certNameOptions.getX500DNHandler().getName(cert.getSubjectX500Principal());
        }
        log.debug("Extracted subject name from certificate: {}", name);
        return name;
    }

    /**
     * Get the list of subject alt name values from the certificate which are of the specified alt name type.
     *
     * @param cert the certificate from which to extract alt names
     * @param altNameType the type of alt name to extract
     *
     * @return the list of certificate subject alt names
     */
    protected List<String> getAltNames(X509Certificate cert, Integer altNameType) {
        log.debug("Extracting alt names from certificate of type: {}", altNameType.toString());
        Integer[] nameTypes = new Integer[] { altNameType };
        List altNames = X509Util.getAltNames(cert, nameTypes);
        List<String> names = new ArrayList<String>();
        for (Object altNameValue : altNames) {
            if (!(altNameValue instanceof String)) {
                log.debug("Skipping non-String certificate alt name value");
            } else {
                names.add((String) altNameValue);
            }
        }
        log.debug("Extracted alt names from certificate: {}", names.toString());
        return names;
    }

}