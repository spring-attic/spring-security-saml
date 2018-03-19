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

import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.security.SecurityPolicyException;
import org.opensaml.compat.security.SecurityPolicyRule;
import org.opensaml.compat.transport.http.HTTPTransport;
import org.opensaml.messaging.context.MessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * A security rule that checks basic HTTP connection properties.
 */
public class HTTPRule implements SecurityPolicyRule {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPRule.class);

    /** Expected content type of the request. */
    private String requiredContentType;

    /** Expected method of the request. */
    private String requiredRequestMethod;

    /** Whether the request must be secure. */
    private boolean requireSecured;

    /**
     * Constructor.
     *
     * @param type expected content type
     * @param method expected request method
     * @param secured whether the request must be secured
     */
    public HTTPRule(String type, String method, boolean secured) {
        requiredContentType = DataTypeHelper.safeTrimOrNullString(type);
        requiredRequestMethod = DataTypeHelper.safeTrimOrNullString(method);
        requireSecured = secured;
    }

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException {

        if (!(((SAMLMessageContext)messageContext).getInboundMessageTransport() instanceof HTTPTransport)) {
            log.debug("Message context was did not contain an HTTP transport, unable to evaluate security rule");
            return;
        }

        doEvaluate(messageContext);
    }

    /**
     * Evaluates if the message context transport, guaranteed to be of type {@link HTTPTransport}, meets all
     * requirements.
     *
     * @param messageContext message context being evaluated
     *
     * @throws SecurityPolicyException thrown if the message context does not meet the requirements of an evaluated rule
     */
    protected void doEvaluate(MessageContext messageContext) throws SecurityPolicyException {
        HTTPTransport transport = (HTTPTransport) ((SAMLMessageContext)messageContext).getInboundMessageTransport();
        evaluateContentType(transport);
        evaluateRequestMethod(transport);
        evaluateSecured(transport);
    }

    /**
     * Checks if the transport is of the correct content type.
     *
     * @param transport transport being evalauted
     *
     * @throws SecurityPolicyException thrown if the content type was an unexpected value
     */
    protected void evaluateContentType(HTTPTransport transport) throws SecurityPolicyException {
        String transportContentType = transport.getHeaderValue("Content-Type");
        if (requiredContentType != null && !transportContentType.startsWith(requiredContentType)) {
            log.error("Invalid content type, expected " + requiredContentType + " but was " + transportContentType);
            throw new SecurityPolicyException("Invalid content type, expected " + requiredContentType + " but was "
                    + transportContentType);
        }
    }

    /**
     * Checks if the transport is of the correct request method.
     *
     * @param transport transport being evalauted
     *
     * @throws SecurityPolicyException thrown if the request method was an unexpected value
     */
    protected void evaluateRequestMethod(HTTPTransport transport) throws SecurityPolicyException {
        String transportMethod = transport.getHTTPMethod();
        if (requiredRequestMethod != null && !transportMethod.equalsIgnoreCase(requiredRequestMethod)) {
            log.error("Invalid request method, expected " + requiredRequestMethod + " but was " + transportMethod);
            throw new SecurityPolicyException("Invalid request method, expected " + requiredRequestMethod + " but was "
                    + transportMethod);
        }
    }

    /**
     * Checks if the transport is secured.
     *
     * @param transport transport being evalauted
     *
     * @throws SecurityPolicyException thrown if the transport is not secure and was required to be
     */
    protected void evaluateSecured(HTTPTransport transport) throws SecurityPolicyException {
        if (requireSecured && !transport.isConfidential()) {
            log.error("Request was required to be secured but was not");
            throw new SecurityPolicyException("Request was required to be secured but was not");
        }
    }
}