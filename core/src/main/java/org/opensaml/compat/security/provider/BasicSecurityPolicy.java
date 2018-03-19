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

import java.util.ArrayList;
import java.util.List;

import org.opensaml.compat.security.SecurityPolicy;
import org.opensaml.compat.security.SecurityPolicyException;
import org.opensaml.compat.security.SecurityPolicyRule;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.security.SecurityException;

/**
 * Basic security policy implementation which evaluates a given set of {@link SecurityPolicyRule} in an ordered manner.
 *
 * A policy evaluates successfully if, and only if, all policy rules evaluate successfully.
 */
public class BasicSecurityPolicy implements SecurityPolicy {

    /** Registered security rules. */
    private ArrayList<SecurityPolicyRule> rules;

    /** Constructor. */
    public BasicSecurityPolicy(){
        rules = new ArrayList<SecurityPolicyRule>(5);
    }

    /** {@inheritDoc} */
    public List<SecurityPolicyRule> getPolicyRules() {
        return rules;
    }

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException, SecurityException {
        for(SecurityPolicyRule rule : getPolicyRules()){
            rule.evaluate(messageContext);
        }
    }
}