/*
 * Copyright 2011 Vladimir Schaefer
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

import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.trust.TrustEngine;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Trust engine for verification of X509 certificates. Uses the supplied trust engine for verification. Trusted credentials
 * are obtained by evaluating the given CredentialSet against the trustEngine. Based on the configuration of the engine
 * either simple certificate equality check is performed or whole PKIX chain can be evaluated.
 */
public class X509TrustManager implements javax.net.ssl.X509TrustManager {

    /**
     * Class logger.
     */
    private final Logger log = LoggerFactory.getLogger(X509TrustManager.class);

    protected CriteriaSet criteriaSet;
    protected TrustEngine<X509Credential> trustEngine;

    /**
     * Creates an X509 trust engine which delegates trust verification to the supplied trust engine. Credentials
     * usable for trust checks are determined by the inserted criteriaSet.
     *
     * @param criteriaSet criteria set to determine trusted credentials within the trust engine
     * @param trustEngine trust engine
     */
    public X509TrustManager(CriteriaSet criteriaSet, TrustEngine<X509Credential> trustEngine) {
        this.criteriaSet = criteriaSet;
        this.trustEngine = trustEngine;
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        log.debug("Client trust verification, always passes");
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        if (x509Certificates == null || x509Certificates.length == 0) {
            throw new IllegalArgumentException("Null or empty certificates list");
        }

        BasicX509Credential credential = new BasicX509Credential();
        X509Certificate x509Certificate = x509Certificates[0];
        credential.setEntityCertificate(x509Certificate);
        credential.setEntityCertificateChain(Arrays.asList(x509Certificates));
        credential.setUsageType(UsageType.UNSPECIFIED);

        EntityIDCriteria entityIDCriteria = criteriaSet.get(EntityIDCriteria.class);
        if (entityIDCriteria != null) {
            credential.setEntityId(entityIDCriteria.getEntityID());
        }

        try {
            log.debug("Checking server trust");
            if (trustEngine.validate(credential, criteriaSet)) {
                log.debug("Server certificate trust verified");
            } else {
                Principal issuerDN = x509Certificate.getIssuerDN();
                Principal subjectDN = x509Certificate.getSubjectDN();
                StringBuilder sb = new StringBuilder(120);
                sb.append("Peer SSL/TLS certificate '").append(subjectDN).append("' ");
                sb.append("issued by '").append(issuerDN).append("' ");
                sb.append("is not trusted, add the certificate or it's CA to your trust store and optionally update tlsKey in extended metadata with the certificate's alias");
                throw new UntrustedCertificateException(sb.toString(), x509Certificates);
            }
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new CertificateException("Error validating certificate", e);
        }

    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

}
