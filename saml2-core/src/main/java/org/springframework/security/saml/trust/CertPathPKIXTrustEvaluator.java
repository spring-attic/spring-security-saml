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
 * Customized PKIX trust evaluator which runs a CertPath verification after obtaining it. This enables e.g. usage
 * of OSCP revocation mechanism in Java 7.
 */
public class CertPathPKIXTrustEvaluator extends org.opensaml.xml.security.x509.CertPathPKIXTrustEvaluator {

    /**
     * Class logger.
     */
    private final Logger log = LoggerFactory.getLogger(MetadataCredentialResolver.class);

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

            log.trace("Building certificate validation path");

            // Construct chain
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult buildResult = (PKIXCertPathBuilderResult) builder.build(params);
            if (log.isDebugEnabled()) {
                logCertPathDebug(buildResult, untrustedCredential.getEntityCertificate());
                log.debug("PKIX validation succeeded for untrusted credential: {}",
                        X509Util.getIdentifiersToken(untrustedCredential, getX500DNHandler()));
            }

            // Validate the chain
            log.trace("Validating certificate path");
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(buildResult.getCertPath(), params);

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

}
