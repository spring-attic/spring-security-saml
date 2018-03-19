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

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.SecurityException;

/**
 * An individual rule that a message context is required to meet in order to be considered valid.
 *
 * Rules <strong>MUST</strong> be thread safe and stateless.
 */
public interface SecurityPolicyRule {

    /**
     * Evaluates the message context against the rule.
     *
     * @param messageContext the message context being evaluated
     *
     * @throws SecurityPolicyException thrown if the message context does not meet the requirements of the rule,
     *          or if there is a non-recoverable error during evaluation
     */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException, SecurityException;
}