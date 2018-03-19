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

import java.util.List;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.SecurityException;

/**
 * A security policy is a collection of {@link SecurityPolicyRule}, evaluated against a {@link MessageContext}, that
 * is meant to determine if a message is well-formed, valid, and otherwise okay to process.
 *
 * Security policies <strong>MUST</strong> be thread safe and stateless.
 */
public interface SecurityPolicy {

    /**
     * Gets the rules that are evaluated for this policy.
     *
     * @return rules that are evaluated for this policy
     */
    public List<SecurityPolicyRule> getPolicyRules();

    /**
     * Evaluates this policy.  Rules are evaluated in the order returned by {@link #getPolicyRules()}.
     *
     * @param messageContext the message context being evaluated
     *
     * @throws SecurityPolicyException thrown if the requirements of the security policy, including those of
     *          any of its rules, are not satisfied by the given message context.  Also thrown if any error
     *          is encountered during evaluation
     */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException, SecurityException;
}