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

import org.opensaml.compat.BackwardsCompatibleMessageContext;
import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.MetadataProvider;
import org.opensaml.compat.MetadataProviderException;
import org.opensaml.compat.transport.http.HTTPInTransport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security policy rule implementation that enforces the AuthnRequestsSigned flag of
 * SAML 2 metadata element @{link {@link SPSSODescriptor}.
 */
public class SAML2AuthnRequestsSignedRule implements SecurityPolicyRule {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(SAML2AuthnRequestsSignedRule.class);

    /** {@inheritDoc} */
    public void evaluate(MessageContext messageContext) throws SecurityPolicyException {
        if (!(messageContext instanceof BackwardsCompatibleMessageContext)) {
            log.debug("Invalid message context type, this policy rule only supports BackwardsCompatibleMessageContext");
            return;
        }
        BackwardsCompatibleMessageContext samlMsgCtx = (BackwardsCompatibleMessageContext) messageContext;

        SAMLObject samlMessage = samlMsgCtx.getInboundSAMLMessage();
        if (! (samlMessage instanceof AuthnRequest) ) {
            log.debug("Inbound message is not an instance of AuthnRequest, skipping evaluation...");
            return;
        }

        String messageIssuer = samlMsgCtx.getInboundMessageIssuer();
        if (DataTypeHelper.isEmpty(messageIssuer)) {
            log.warn("Inbound message issuer was empty, unable to evaluate rule");
            return;
        }

        MetadataProvider metadataProvider = samlMsgCtx.getMetadataProvider();
        if (metadataProvider == null) {
            log.warn("Message context did not contain a metadata provider, unable to evaluate rule");
            return;
        }

        SPSSODescriptor spssoRole;
        try {
            spssoRole = (SPSSODescriptor) metadataProvider
                .getRole(messageIssuer, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        } catch (MetadataProviderException e) {
            log.warn("Error resolving SPSSODescriptor metadata for entityID '{}': {}", messageIssuer, e.getMessage());
            throw new SecurityPolicyException("Error resolving metadata for entity ID", e);
        }

        if (spssoRole == null) {
            log.warn("SPSSODescriptor role metadata for entityID '{}' could not be resolved", messageIssuer);
            return;
        }

        if (spssoRole.isAuthnRequestsSigned() == Boolean.TRUE) {
            if (! isMessageSigned(samlMsgCtx)) {
                log.error("SPSSODescriptor for entity ID '{}' indicates AuthnRequests must be signed, "
                        + "but inbound message was not signed", messageIssuer);
                throw new SecurityPolicyException("Inbound AuthnRequest was required to be signed but was not");
            }
        } else {
            log.debug("SPSSODescriptor for entity ID '{}' does not require AuthnRequests to be signed", messageIssuer);
        }

    }

    /**
     * Determine whether the inbound message is signed.
     *
     * @param messageContext the message context being evaluated
     * @return true if the inbound message is signed, otherwise false
     */
    protected boolean isMessageSigned(BackwardsCompatibleMessageContext messageContext) {
        // TODO this really should be determined by the decoders and supplied to the rule
        // in some fashion, to handle binding-specific signature mechanisms. See JIRA issue JOWS-4.
        //
        // For now evaluate here inline for XML Signature and HTTP-Redirect and HTTP-Post-SimpleSign.

        SAMLObject samlMessage = messageContext.getInboundSAMLMessage();
        if (samlMessage instanceof SignableSAMLObject) {
            SignableSAMLObject signableMessage = (SignableSAMLObject) samlMessage;
            if (signableMessage.isSigned()) {
                return true;
            }
        }

        // This handles HTTP-Redirect and HTTP-POST-SimpleSign bindings.
        HTTPInTransport inTransport = (HTTPInTransport) messageContext.getInboundMessageTransport();
        String sigParam = inTransport.getParameterValue("Signature");
        return !DataTypeHelper.isEmpty(sigParam);
    }

}
