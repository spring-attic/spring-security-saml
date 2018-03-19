/*
 * Copyright 2009 Mandus Elfving
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opensaml.saml2.binding.decoding;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.util.List;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.compat.BackwardsCompatibleMessageContext;
import org.opensaml.compat.DataTypeHelper;
import org.opensaml.compat.MetadataProvider;
import org.opensaml.compat.MetadataProviderException;
import org.opensaml.compat.transport.InTransport;
import org.opensaml.compat.transport.http.HTTPInTransport;
import org.opensaml.compat.transport.http.HTTPOutTransport;
import org.opensaml.compat.transport.http.HttpServletRequestAdapter;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.ws.transport.http.LocationAwareInTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;

/**
 * Class to decode HTTP artifact binding and request the SAML message through the artifact request
 * response protocol with an IDP. At the moment only supports GET requests.
 *
 * @author Mandus Elfving
 */
public class HTTPArtifactDecoderImpl extends HttpClientResponseSOAP11Decoder implements MessageDecoder<SAMLObject> {

    private final Logger log = LoggerFactory.getLogger(HTTPArtifactDecoderImpl.class);

    private ArtifactResolutionProfile resolutionProfile;
    private MessageContext context;

    public HTTPArtifactDecoderImpl(ArtifactResolutionProfile resolutionProfile,
                                   ParserPool parserPool,
                                   MessageContext context) {
        super();
        this.setParserPool(parserPool);
        this.resolutionProfile = resolutionProfile;
        this.context = context;
    }

    protected boolean isIntendedDestinationEndpointURIRequired(BackwardsCompatibleMessageContext samlMsgCtx) {
        return false;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    @Override
    protected void doDecode() throws MessageDecodingException {
        doDecode(getMessageContext());
    }

    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {

        if (!(messageContext instanceof BackwardsCompatibleMessageContext)) {
            log.error("Invalid message context type, this decoder only support SAMLMessageContext");
            throw new MessageDecodingException(
                    "Invalid message context type, this decoder only support SAMLMessageContext");
        }

        org.springframework.security.saml.context.SAMLMessageContext samlMessageContext = (org.springframework.security.saml.context.SAMLMessageContext) messageContext;

        if (!(samlMessageContext.getInboundMessageTransport() instanceof HTTPInTransport)) {
            log.error("Invalid inbound message transport type, this decoder only support HTTPInTransport");
            throw new MessageDecodingException("Invalid inbound message transport type, this decoder only support HTTPInTransport");
        }

        HTTPInTransport inTransport = (HTTPInTransport) samlMessageContext.getInboundMessageTransport();
        HTTPOutTransport outTransport = (HTTPOutTransport) samlMessageContext.getOutboundMessageTransport();

        /*
         * Artifact parameter.
         */
        String artifactId = DataTypeHelper.safeTrimOrNullString(inTransport.getParameterValue("SAMLart"));
        if (artifactId == null) {
            log.error("SAMLart parameter was missing or did not contain a value.");
            throw new MessageDecodingException("SAMLArt parameter was missing or did not contain a value.");
        }

        log.debug("Artifact id: {}", artifactId);

        /*
         * Relay state parameter.
         */
        samlMessageContext.setRelayState(inTransport.getParameterValue("RelayState"));

        log.debug("Decoded RelayState: {}", samlMessageContext.getRelayState());

        SAMLObject message = resolutionProfile.resolveArtifact(samlMessageContext, artifactId, getActualReceiverEndpointURI(samlMessageContext));

        // Fix potentially overwritten transports and set constants
        samlMessageContext.setInboundSAMLMessage(message);
        samlMessageContext.setInboundMessageTransport(inTransport);
        samlMessageContext.setOutboundMessageTransport(outTransport);
        samlMessageContext.setInboundSAMLBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

        populateMessageContext(samlMessageContext);

    }

    protected String getActualReceiverEndpointURI(BackwardsCompatibleMessageContext messageContext) throws MessageDecodingException {

        InTransport inTransport = messageContext.getInboundMessageTransport();
        if (inTransport instanceof LocationAwareInTransport) {
            return ((LocationAwareInTransport)inTransport).getLocalAddress();
        } else {
            if (! (inTransport instanceof HttpServletRequestAdapter)) {
                log.error("Message context InTransport instance was an unsupported type: {}",
                          inTransport.getClass().getName());
                throw new MessageDecodingException("Message context InTransport instance was an unsupported type");
            }
            HttpServletRequest httpRequest = ((HttpServletRequestAdapter)inTransport).getWrappedRequest();

            StringBuffer urlBuilder = httpRequest.getRequestURL();

            return urlBuilder.toString();
        }

    }

    protected void populateMessageContext(BackwardsCompatibleMessageContext messageContext) throws MessageDecodingException {
        populateMessageIdIssueInstantIssuer(messageContext);
        populateRelyingPartyMetadata(messageContext);
    }

    protected void populateRelyingPartyMetadata(BackwardsCompatibleMessageContext messageContext) throws MessageDecodingException {
        MetadataProvider metadataProvider = messageContext.getMetadataProvider();
        try {
            if (metadataProvider != null) {
                EntityDescriptor relyingPartyMD = metadataProvider.getEntityDescriptor(messageContext
                                                                                           .getInboundMessageIssuer());
                messageContext.setPeerEntityMetadata(relyingPartyMD);

                QName relyingPartyRole = messageContext.getPeerEntityRole();
                if (relyingPartyMD != null && relyingPartyRole != null) {
                    List<RoleDescriptor> roles = relyingPartyMD.getRoleDescriptors(relyingPartyRole,
                                                                                   SAMLConstants.SAML20P_NS);
                    if (roles != null && roles.size() > 0) {
                        messageContext.setPeerEntityRoleMetadata(roles.get(0));
                    }
                }
            }
        } catch (MetadataProviderException e) {
            log.error("Error retrieving metadata for relying party " + messageContext.getInboundMessageIssuer(), e);
            throw new MessageDecodingException("Error retrieving metadata for relying party "
                                                   + messageContext.getInboundMessageIssuer(), e);
        }
    }

    protected void populateMessageIdIssueInstantIssuer(BackwardsCompatibleMessageContext messageContext)
        throws MessageDecodingException {
        if (!(messageContext instanceof BackwardsCompatibleMessageContext)) {
            log.debug("Invalid message context type, this policy rule only support SAMLMessageContext");
            return;
        }
        BackwardsCompatibleMessageContext samlMsgCtx = messageContext;

        SAMLObject samlMsg = samlMsgCtx.getInboundSAMLMessage();
        if (samlMsg == null) {
            log.error("Message context did not contain inbound SAML message");
            throw new MessageDecodingException("Message context did not contain inbound SAML message");
        }

        if (samlMsg instanceof RequestAbstractType) {
            log.debug("Extracting ID, issuer and issue instant from request");
            extractRequestInfo(samlMsgCtx, (RequestAbstractType) samlMsg);
        } else if (samlMsg instanceof StatusResponseType) {
            log.debug("Extracting ID, issuer and issue instant from status response");
            extractResponseInfo(samlMsgCtx, (StatusResponseType) samlMsg);
        } else {
            throw new MessageDecodingException("SAML 2 message was not a request or a response");
        }

        if (samlMsgCtx.getInboundMessageIssuer() == null) {
            log.warn("Issuer could not be extracted from SAML 2 message");
        }

    }

    protected void extractRequestInfo(BackwardsCompatibleMessageContext messageContext, RequestAbstractType request)
        throws MessageDecodingException {
        messageContext.setInboundSAMLMessageId(request.getID());
        messageContext.setInboundSAMLMessageIssueInstant(request.getIssueInstant());
        messageContext.setInboundMessageIssuer(extractEntityId(request.getIssuer()));
    }

    protected String extractEntityId(Issuer issuer) throws MessageDecodingException {
        if (issuer != null) {
            if (issuer.getFormat() == null || issuer.getFormat().equals(NameIDType.ENTITY)) {
                return issuer.getValue();
            } else {
                throw new MessageDecodingException("SAML 2 Issuer is not of ENTITY format type");
            }
        }

        return null;
    }

    protected void extractResponseInfo(BackwardsCompatibleMessageContext messageContext, StatusResponseType statusResponse)
        throws MessageDecodingException {

        messageContext.setInboundSAMLMessageId(statusResponse.getID());
        messageContext.setInboundSAMLMessageIssueInstant(statusResponse.getIssueInstant());

        // If response doesn't have an issuer, look at the first
        // enclosed assertion
        String messageIssuer = null;
        if (statusResponse.getIssuer() != null) {
            messageIssuer = extractEntityId(statusResponse.getIssuer());
        } else if (statusResponse instanceof Response) {
            List<Assertion> assertions = ((Response) statusResponse).getAssertions();
            if (assertions != null && assertions.size() > 0) {
                log.info("Status response message had no issuer, attempting to extract issuer from enclosed Assertion(s)");
                String assertionIssuer;
                for (Assertion assertion : assertions) {
                    if (assertion != null && assertion.getIssuer() != null) {
                        assertionIssuer = extractEntityId(assertion.getIssuer());
                        if (messageIssuer != null && !messageIssuer.equals(assertionIssuer)) {
                            throw new MessageDecodingException("SAML 2 assertions, within response "
                                                                   + statusResponse.getID() + " contain different issuer IDs");
                        }
                        messageIssuer = assertionIssuer;
                    }
                }
            }
        }

        messageContext.setInboundMessageIssuer(messageIssuer);
    }

}