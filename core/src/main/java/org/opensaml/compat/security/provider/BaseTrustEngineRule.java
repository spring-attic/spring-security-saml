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

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.compat.security.SecurityPolicyException;
import org.opensaml.compat.security.SecurityPolicyRule;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.SecurityException;
import org.opensaml.security.trust.TrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base rule which uses a trust engine to evaluate a token extracted from the request or message.
 *
 * @param <TokenType> type of token which is being evaluated by the underlying trust engine
 */
public abstract class BaseTrustEngineRule<TokenType> implements SecurityPolicyRule {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(BaseTrustEngineRule.class);

    /** Trust engine used to verify the particular token type. */
    private TrustEngine<TokenType> trustEngine;

    /**
     * Constructor.
     *
     * @param engine Trust engine used to verify the particular token type
     */
    public BaseTrustEngineRule(TrustEngine<TokenType> engine) {
        trustEngine = engine;
    }

    /**
     * Gets the engine used to validate the untrusted token.
     *
     * @return engine engine used to validate the untrusted token
     */
    protected TrustEngine<TokenType> getTrustEngine() {
        return trustEngine;
    }

    /**
     * Subclasses are required to implement this method to build a criteria set for the trust engine
     * according to trust engine and application-specific needs.
     *
     * @param entityID the candidate issuer entity ID which is being evaluated
     * @param messageContext the message context which is being evaluated
     * @return a newly constructly set of criteria suitable for the configured trust engine
     * @throws SecurityPolicyException thrown if criteria set can not be constructed
     */
    protected abstract CriteriaSet buildCriteriaSet(String entityID, MessageContext messageContext)
        throws SecurityPolicyException;

    /**
     * Evaluate the token using the configured trust engine against criteria built using
     * the specified candidate issuer entity ID and message context information.
     *
     * @param token the token to be evaluated
     * @param entityID the candidate issuer entity ID which is being evaluated
     * @param messageContext the message context which is being evaluated
     * @return true if the token satisfies the criteria as determined by the trust engine, otherwise false
     * @throws SecurityPolicyException thrown if there is a fatal error during trust engine evaluation
     */
    protected boolean evaluate(TokenType token, String entityID, MessageContext messageContext)
        throws SecurityPolicyException, SecurityException {

        CriteriaSet criteriaSet = buildCriteriaSet(entityID, messageContext);
        if (criteriaSet == null) {
            log.error("Returned criteria set was null, can not perform trust engine evaluation of token");
            throw new SecurityPolicyException("Returned criteria set was null");
        }

        return evaluate(token, criteriaSet);
    }

    /**
     * Evaluate the token against the specified criteria using the configured trust engine.
     *
     * @param token the token to be evaluated
     * @param criteriaSet the set of criteria against which to evaluate the token
     * @return true if the token satisfies the criteria as determined by the trust engine, otherwise false
     * @throws SecurityPolicyException thrown if there is a fatal error during trust engine evaluation
     */
    protected boolean evaluate(TokenType token, CriteriaSet criteriaSet)
        throws SecurityPolicyException, SecurityException {
        try {
            return getTrustEngine().validate(token, criteriaSet);
        } catch (SecurityException e) {
            log.error("There was an error evaluating the request's token using the trust engine", e);
            throw new SecurityPolicyException("Error during trust engine evaluation of the token", e);
        }
    }

}