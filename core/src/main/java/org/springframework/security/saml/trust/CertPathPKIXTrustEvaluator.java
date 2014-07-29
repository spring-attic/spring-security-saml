/* Copyright 2011 Vladimir Schafer
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
package org.springframework.security.saml.trust;

import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.x509.PKIXValidationInformation;
import org.opensaml.xml.security.x509.PKIXValidationOptions;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.x509.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.cert.*;

/**
 * PKIX trust evaluator based on Java CertPath API. Class first constructs PKIXBuilderParameters using call to
 * getPKIXBuilderParameters. Parameters consult the options property for defaults of isForceRevocationEnabled,
 * forcedRevocation, policyMappingInhibited, anyPolicyInhibited and initialPolicies settings. System then constructs
 * CertPathBuilder with PKIX algorithm and selected securityProvider and builds the certificate path.
 *
 * If path building succeeds system also optionally verifies the resulting certificate chain using CertPathValidator.
 * In earlier Java versions the builder implementation doesn't support e.g. OCSP checking. Running a separate path
 * validation makes it possible to use these features..
 */
public class CertPathPKIXTrustEvaluator extends org.opensaml.xml.security.x509.CertPathPKIXTrustEvaluator {

    /**
     * Class logger.
     */
    private final Logger log = LoggerFactory.getLogger(MetadataCredentialResolver.class);

    /**
     * Security provider for loading of PKIX classes.
     */
    private String securityProvider = null;

    /**
     * Flag indicating whether additional validation of the cert path is required.
     */
    private boolean validateCertPath = true;

    public CertPathPKIXTrustEvaluator() {
    }

    public CertPathPKIXTrustEvaluator(PKIXValidationOptions newOptions) {
        super(newOptions);
    }

    /** {@inheritDoc} */
    public boolean validate(PKIXValidationInformation validationInfo, X509Credential untrustedCredential)
            throws org.opensaml.xml.security.SecurityException {

        if (log.isDebugEnabled()) {
            log.debug("Attempting PKIX path validation on untrusted credential: {}",
                    X509Util.getIdentifiersToken(untrustedCredential, getX500DNHandler()));
        }

        try {

            PKIXBuilderParameters params = getPKIXBuilderParameters(validationInfo, untrustedCredential);

            // Construct certificate path
            CertPathBuilder builder;
            if (securityProvider == null) {
                builder = CertPathBuilder.getInstance("PKIX");
                log.trace("Building certificate path using default security provider");
            } else {
                builder = CertPathBuilder.getInstance("PKIX", securityProvider);
                log.trace("Building certificate path using security provider {}", securityProvider);
            }

            PKIXCertPathBuilderResult buildResult = (PKIXCertPathBuilderResult) builder.build(params);
            if (log.isDebugEnabled()) {
                logCertPathDebug(buildResult, untrustedCredential.getEntityCertificate());
                log.debug("PKIX validation succeeded for untrusted credential: {}",
                        X509Util.getIdentifiersToken(untrustedCredential, getX500DNHandler()));
            }

            if (validateCertPath) {
                log.trace("Validating certificate path");
                // Validate the certificate path
                CertPathValidator validator;
                if (securityProvider == null) {
                    validator = CertPathValidator.getInstance("PKIX");
                } else {
                    validator = CertPathValidator.getInstance("PKIX", securityProvider);
                }
                validator.validate(buildResult.getCertPath(), params);
            }

            return true;

        } catch (CertPathBuilderException e) {
            if (log.isTraceEnabled()) {
                log.trace("PKIX path construction failed for untrusted credential: "
                        + X509Util.getIdentifiersToken(untrustedCredential, getX500DNHandler()), e);
            } else {
                log.error("PKIX path construction failed for untrusted credential: "
                        + X509Util.getIdentifiersToken(untrustedCredential, getX500DNHandler()) + ": " + e.getMessage());
            }
            return false;
        } catch (GeneralSecurityException e) {
            log.error("PKIX validation failure", e);
            throw new SecurityException("PKIX validation failure", e);
        }
    }

    /**
     * Log information from the constructed cert path at level debug.
     *
     * @param buildResult the PKIX cert path builder result containing the cert path and trust anchor
     * @param targetCert the cert untrusted certificate that was being evaluated
     */
    private void logCertPathDebug(PKIXCertPathBuilderResult buildResult, X509Certificate targetCert) {
        log.debug("Built valid PKIX cert path");
        log.debug("Target certificate: {}", getX500DNHandler().getName(targetCert.getSubjectX500Principal()));
        for (Certificate cert : buildResult.getCertPath().getCertificates()) {
            log.debug("CertPath certificate: {}", getX500DNHandler().getName(((X509Certificate) cert)
                    .getSubjectX500Principal()));
        }
        TrustAnchor ta = buildResult.getTrustAnchor();
        if (ta.getTrustedCert() != null) {
            log.debug("TrustAnchor: {}", getX500DNHandler().getName(ta.getTrustedCert().getSubjectX500Principal()));
        } else if (ta.getCA() != null) {
            log.debug("TrustAnchor: {}", getX500DNHandler().getName(ta.getCA()));
        } else {
            log.debug("TrustAnchor: {}", ta.getCAName());
        }
    }

    /**
     * Sets security provider used to instantiate CertPathBuilder and CertPathValidator instances from the
     * CertPathBuilder and CertPathValidator factories. When no value is specified system will use the default
     * security provider.
     *
     * Default value is null.
     *
     * @param provider name of the security provider (e.g. BC for BouncyCastle)
     */
    public void setSecurityProvider(String provider) {
        this.securityProvider = provider;
    }

    /**
     * Flag indicating whether to execute additional certificate path validation using the java.security.cert.CertPathValidator
     * factory. The CertPathBuilder typically performs most PKIX verifications already, but in some cases (e.g.
     * for OCSP support and CRLDP support in certain Java versions) it is necessary to run additional checkins in the
     * validator.
     *
     * Default value is false.
     *
     * @param validateCertPath flag indicating usage of the CertPathValidator.
     */
    public void setValidateCertPath(boolean validateCertPath) {
        this.validateCertPath = validateCertPath;
    }

}
