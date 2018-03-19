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

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.compat.MetadataCriteria;
import org.opensaml.compat.security.provider.CertificateNameOptions;
import org.opensaml.compat.security.provider.ClientCertAuthRule;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * SAML specialization of {@link ClientCertAuthRule} which provides support for X509Credential trust engine validation
 * based on SAML metadta.
 */
public class SAMLMDClientCertAuthRule extends ClientCertAuthRule {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(SAMLMDClientCertAuthRule.class);

    /**
     * Constructor.
     *
     * @param engine Trust engine used to verify the request X509Credential
     * @param nameOptions options for deriving issuer names from an X.509 certificate
     */
    public SAMLMDClientCertAuthRule(TrustEngine<X509Credential> engine, CertificateNameOptions nameOptions) {
        super(engine, nameOptions);
    }

    /** {@inheritDoc} */
    protected CriteriaSet buildCriteriaSet(String entityID, MessageContext messageContext)
        throws SecurityPolicyException {

        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Supplied message context was not an instance of SAMLMessageContext, can not build criteria set from SAML metadata parameters");
            throw new SecurityPolicyException("Supplied message context was not an instance of SAMLMessageContext");
        }

        SAMLMessageContext samlContext = (SAMLMessageContext) messageContext;

        CriteriaSet criteriaSet = super.buildCriteriaSet(entityID, messageContext);
        MetadataCriteria mdCriteria =
            new MetadataCriteria(samlContext.getPeerEntityRole(), samlContext.getInboundSAMLProtocol());
        criteriaSet.add(mdCriteria);

        return criteriaSet;
    }
}