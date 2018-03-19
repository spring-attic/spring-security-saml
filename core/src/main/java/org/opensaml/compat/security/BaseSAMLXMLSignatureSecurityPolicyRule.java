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
import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.MetadataCriteria;
import org.opensaml.compat.UsageCriteria;
import org.opensaml.compat.security.provider.BaseTrustEngineRule;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.xmlsec.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Base class for SAML security policy rules which evaluate a signature with a signature trust engine.
 */
public abstract class BaseSAMLXMLSignatureSecurityPolicyRule extends BaseTrustEngineRule<Signature> {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(BaseSAMLXMLSignatureSecurityPolicyRule.class);

    /**
     * Constructor.
     *
     * @param engine Trust engine used to verify the signature
     */
    public BaseSAMLXMLSignatureSecurityPolicyRule(TrustEngine<Signature> engine) {
        super(engine);
    }

    /** {@inheritDoc} */
    protected CriteriaSet buildCriteriaSet(String entityID, MessageContext messageContext)
        throws SecurityPolicyException {
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Supplied message context was not an instance of SAMLMessageContext, can not build criteria set from SAML metadata parameters");
            throw new SecurityPolicyException("Supplied message context was not an instance of SAMLMessageContext");
        }

        SAMLMessageContext samlContext = (SAMLMessageContext) messageContext;

        CriteriaSet criteriaSet = new CriteriaSet();
        if (! DataTypeHelper.isEmpty(entityID)) {
            criteriaSet.add(new EntityIdCriterion(entityID) );
        }

        MetadataCriteria mdCriteria =
            new MetadataCriteria(samlContext.getPeerEntityRole(), samlContext.getInboundSAMLProtocol());
        criteriaSet.add(mdCriteria);

        criteriaSet.add( new UsageCriteria(UsageType.SIGNING) );

        return criteriaSet;
    }

}
