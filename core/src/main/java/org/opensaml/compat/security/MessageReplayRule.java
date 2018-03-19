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

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security policy rule implementation that which checks for replay of SAML messages.
 */
public class MessageReplayRule implements SecurityPolicyRule {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(MessageReplayRule.class);

    /** Message replay cache instance to use. */
    private ReplayCache replayCache;

    /** Whether this rule is required to be met. */
    private boolean requiredRule;

    /**
     * Constructor.
     *
     * @param newReplayCache the new replay cache instance
     */
    public MessageReplayRule(ReplayCache newReplayCache) {
        replayCache = newReplayCache;
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
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.debug("Invalid message context type, this policy rule only supports SAMLMessageContext");
            return;
        }

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

        String messageIsuer = DatatypeHelper.safeTrimOrNullString(samlMsgCtx.getInboundMessageIssuer());
        if (messageIsuer == null) {
            if (requiredRule) {
                log.warn("Message contained no Issuer ID, replay check not possible");
                throw new SecurityPolicyException("Message contained no Issuer ID, replay check not possible");
            }
            return;
        }

        String messageId = DatatypeHelper.safeTrimOrNullString(samlMsgCtx.getInboundSAMLMessageId());
        if (messageId == null) {
            if (requiredRule) {
                log.warn("Message contained no ID, replay check not possible");
                throw new SecurityPolicyException("SAML message from issuer " + messageIsuer + " did not contain an ID");
            }
            return;
        }

        if (replayCache.isReplay(messageIsuer, messageId)) {
            log.warn("Replay detected of message '" + messageId + "' from issuer " + messageIsuer);
            throw new SecurityPolicyException("Rejecting replayed message ID '" + messageId + "' from issuer "
                    + messageIsuer);
        }

    }
}