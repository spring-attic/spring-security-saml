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

import org.joda.time.DateTime;
import org.opensaml.compat.BackwardsCompatibleMessageContext;
import org.opensaml.messaging.context.MessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security policy rule implementation that checks for validity of SAML message issue instant date and time.
 */
public class IssueInstantRule implements SecurityPolicyRule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(IssueInstantRule.class);

    /**
     * Clock skew - the number of seconds before a lower time bound, or after an upper time bound, to consider still
     * acceptable.
     */
    private int clockSkew;

    /** Number of seconds after a message issue instant after which the message is considered expired. */
    private int expires;

    /** Whether this rule is required to be met. */
    private boolean requiredRule;

    /**
     * Constructor.
     *
     * @param newClockSkew the new clock skew value (seconds)
     * @param newExpires the new expiration value (seconds)
     */
    public IssueInstantRule(int newClockSkew, int newExpires) {
        clockSkew = newClockSkew;
        expires = newExpires;
        requiredRule = true;
    }

    /**
     * Gets whether this rule is required to be met.
     *
     * @return whether this rule is required to be met
     */
    public boolean isRequiredRule() {
        return requiredRule;
    }

    /**
     * Sets whether this rule is required to be met.
     *
     * @param required whether this rule is required to be met
     */
    public void setRequiredRule(boolean required) {
        requiredRule = required;
    }

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException {
        if (!(messageContext instanceof BackwardsCompatibleMessageContext)) {
            log.debug("Invalid message context type, this policy rule only supports BackwardsCompatibleMessageContext");
            return;
        }
        BackwardsCompatibleMessageContext samlMsgCtx = (BackwardsCompatibleMessageContext) messageContext;

        if (samlMsgCtx.getInboundSAMLMessageIssueInstant() == null) {
            if(requiredRule){
                log.warn("Inbound SAML message issue instant not present in message context");
                throw new SecurityPolicyException("Inbound SAML message issue instant not present in message context");
            }else{
                return;
            }
        }

        DateTime issueInstant = samlMsgCtx.getInboundSAMLMessageIssueInstant();
        DateTime now = new DateTime();
        DateTime latestValid = now.plusSeconds(clockSkew);
        DateTime expiration = issueInstant.plusSeconds(clockSkew + expires);

        // Check message wasn't issued in the future
        if (issueInstant.isAfter(latestValid)) {
            log.warn("Message was not yet valid: message time was {}, latest valid is: {}", issueInstant, latestValid);
            throw new SecurityPolicyException("Message was rejected because was issued in the future");
        }

        // Check message has not expired
        if (expiration.isBefore(now)) {
            log.warn("Message was expired: message issue time was '" + issueInstant + "', message expired at: '"
                    + expiration + "', current time: '" + now + "'");
            throw new SecurityPolicyException("Message was rejected due to issue instant expiration");
        }

    }
}