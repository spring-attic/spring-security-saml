/* Copyright 2009 Vladimir Schäfer
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
package org.springframework.security.saml.processor;

import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.ws.transport.InTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.Assert;

import javax.xml.namespace.QName;
import java.util.Arrays;
import java.util.Collection;

/**
 * Processor is capable of parsing SAML message from HttpServletRequest and populate the SAMLMessageContext
 * for further validations.
 *
 * @author Vladimir Schäfer
 */
public class SAMLProcessorImpl implements SAMLProcessor {

    private final static Logger log = LoggerFactory.getLogger(SAMLProcessorImpl.class);

    /**
     * Bindings supported by this processor.
     */
    protected Collection<SAMLBinding> bindings;

    /**
     * Creates a processor supporting a single binding.
     *
     * @param binding binding
     */
    public SAMLProcessorImpl(SAMLBinding binding) {
        this.bindings = Arrays.asList(binding);
    }

    /**
     * Creates a processor supporting multiple bindings.
     *
     * @param bindings bindings
     */
    public SAMLProcessorImpl(Collection<SAMLBinding> bindings) {
        this.bindings = bindings;
    }

    /**
     * Loads incoming SAML message using one of the configured bindings and populates the SAMLMessageContext object with it.
     * The context is expected to contain inboundMessageTransport and outboundMessageTransport. In case localEntityId,
     * localEntityRole or peerEntityRole is set it will be used, otherwise default SP is loaded as a local entity and IDP presumed as a peer.
     *
     * @param samlContext context
     * @param binding     to use for message extraction
     * @return SAML message context with filled information about the message
     * @throws SAMLException             error retrieving the message from the request
     * @throws MetadataProviderException error retrieving metadata
     * @throws MessageDecodingException  error decoding the message
     * @throws org.opensaml.xml.security.SecurityException
     *                                   error verifying message
     */
    public SAMLMessageContext retrieveMessage(SAMLMessageContext samlContext, SAMLBinding binding) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException {

        log.debug("Retrieving message using binding {}", binding.getBindingURI());

        verifyContext(samlContext);
        populateSecurityPolicy(samlContext, binding);

        QName peerEntityRole = samlContext.getPeerEntityRole();
        if (peerEntityRole == null) {
            peerEntityRole = IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
        }
        samlContext.setPeerEntityRole(peerEntityRole);
        samlContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        samlContext.setInboundSAMLBinding(binding.getBindingURI());

        // Decode the message
        MessageDecoder decoder = binding.getMessageDecoder();
        decoder.decode(samlContext);

        if (samlContext.getPeerEntityMetadata() == null) {
            throw new MetadataProviderException("Metadata for issuer " + samlContext.getInboundMessageIssuer() + " wasn't found");
        }

        samlContext.setPeerEntityId(samlContext.getPeerEntityMetadata().getEntityID());
        samlContext.setPeerExtendedMetadata(((MetadataManager) samlContext.getMetadataProvider()).getExtendedMetadata(samlContext.getPeerEntityId()));

        return samlContext;

    }

    /**
     * Populates security policy to use for the incoming message and sets it in the samlContext as securityPolicyResolver.
     * SecurityPolicy is populated using getSecurityPolicy method of the used binding.
     *
     * @param samlContext saml context to set the policy to
     * @param binding     binding used to retrieve the message
     */
    protected void populateSecurityPolicy(SAMLMessageContext samlContext, SAMLBinding binding) {

        SecurityPolicy policy = new BasicSecurityPolicy();
        binding.getSecurityPolicy(policy.getPolicyRules(), samlContext);
        StaticSecurityPolicyResolver resolver = new StaticSecurityPolicyResolver(policy);
        samlContext.setSecurityPolicyResolver(resolver);

    }


    /**
     * Loads incoming SAML message using one of the configured bindings and populates the SAMLMessageContext object with it.
     *
     * @param samlContext saml context
     * @param binding     to use for message extraction
     * @return SAML message context with filled information about the message
     * @throws org.opensaml.common.SAMLException
     *          error retrieving the message from the request
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException
     *          error retrieving metadat
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException
     *          error decoding the message
     * @throws org.opensaml.xml.security.SecurityException
     *          error verifying message
     */
    public SAMLMessageContext retrieveMessage(SAMLMessageContext samlContext, String binding) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException {

        return retrieveMessage(samlContext, getBinding(binding));

    }

    /**
     * Loads incoming SAML message using one of the configured bindings and populates the SAMLMessageContext object with it.
     *
     * @param samlContext saml context
     * @return SAML message context with filled information about the message
     * @throws org.opensaml.common.SAMLException
     *          error retrieving the message from the request
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException
     *          error retrieving metadat
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException
     *          error decoding the message
     * @throws org.opensaml.xml.security.SecurityException
     *          error verifying message
     */
    public SAMLMessageContext retrieveMessage(SAMLMessageContext samlContext) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException {

        return retrieveMessage(samlContext, getBinding(samlContext.getInboundMessageTransport()));

    }

    /**
     * Method sends SAML message contained in the context to the specified peerEntityEnpoint. Binding is automatically
     * determined based on the selected endpoint.
     *
     * @param samlContext context
     * @param sign        true when sent message should be signed
     * @return resulting context, might be a copy
     */
    public SAMLMessageContext sendMessage(SAMLMessageContext samlContext, boolean sign)
            throws SAMLException, MetadataProviderException, MessageEncodingException {

        Endpoint endpoint = samlContext.getPeerEntityEndpoint();
        if (endpoint == null) {
            throw new SAMLException("Could not get peer entity endpoint");
        }

        return sendMessage(samlContext, sign, getBinding(endpoint));

    }

    public SAMLMessageContext sendMessage(SAMLMessageContext samlContext, boolean sign, String bindingName) throws SAMLException, MetadataProviderException, MessageEncodingException {

        return sendMessage(samlContext, sign, getBinding(bindingName));

    }

    /**
     * Sends SAML message using the given binding. Context is expected to contain outboundMessageTransport. In case localEntityId or localEntityRole
     * is set, it is used, default SP is used otherwise.
     *
     * @param samlContext context
     * @param sign        if true sent message is signed
     * @param binding     binding to use
     * @return context
     * @throws SAMLException             in case message can't be sent
     * @throws MessageEncodingException  in case message encoding fails
     * @throws MetadataProviderException in case metadata for required entities is not found
     */
    protected SAMLMessageContext sendMessage(SAMLMessageContext samlContext, boolean sign, SAMLBinding binding) throws SAMLException, MetadataProviderException, MessageEncodingException {

        verifyContext(samlContext);

        if (sign) {
            Assert.notNull(samlContext.getLocalSigningCredential(), "Cannot sign outgoing message as no signing credential is set in the context");
            samlContext.setOutboundSAMLMessageSigningCredential(samlContext.getLocalSigningCredential());
        }

        MessageEncoder encoder = binding.getMessageEncoder();
        encoder.encode(samlContext);

        return samlContext;

    }

    /**
     * Verifies that context contains all the required information related to the local entity.
     *
     * @param samlContext context to populate
     * @throws MetadataProviderException in case metadata do not contain expected entities
     */
    protected void verifyContext(SAMLMessageContext samlContext) throws MetadataProviderException {

        Assert.notNull(samlContext.getMetadataProvider(), "Metadata provider must be set in the context");
        Assert.notNull(samlContext.getLocalEntityId(), "Local entity id must be set in the context");
        Assert.notNull(samlContext.getLocalEntityRole(), "Local entity role must be set in the context");
        Assert.notNull(samlContext.getLocalEntityMetadata(), "Local entity metadata must be set in the context");
        Assert.notNull(samlContext.getLocalEntityRoleMetadata(), "Local entity role metadata must be set in the context");
        Assert.notNull(samlContext.getLocalExtendedMetadata(), "Local extended metadata must be set in the context");
        Assert.notNull(samlContext.getLocalTrustEngine(), "SignatureTrustEngine must be set in the samlContext");
        Assert.notNull(samlContext.getLocalSSLTrustEngine(), "SSL Trust Engine must be set in the samlContext");

    }

    /**
     * Analyzes the transport object and returns the first binding capable of sending/extracting a SAML message from to/from it.
     * In case no binding is found SAMLException is thrown.
     *
     * @param transport transport type to get binding for
     * @return decoder
     * @throws SAMLException in case no suitable decoder is found for given request
     */
    protected SAMLBinding getBinding(InTransport transport) throws SAMLException {

        for (SAMLBinding binding : bindings) {
            if (binding.supports(transport)) {
                return binding;
            }
        }

        throw new SAMLException("Unsupported request");

    }

    /**
     * Determines binding to be used for the given endpoint. By default binding returned from getBinding call on the
     * endpoint is used. Speciall handling is used for Holder of Key WebSSO profile endpoints where real binding
     * is stored under hoksso:ProtocolBinding attribute.
     *
     * @param endpoint endpoint t
     * @return binding
     * @throws SAMLException in case binding can't be found
     * @throws MetadataProviderException in case binding of the endpoint can't be determined
     * @see SAMLUtil#getBindingForEndpoint(org.opensaml.saml2.metadata.Endpoint)
     */
    protected SAMLBinding getBinding(Endpoint endpoint) throws SAMLException, MetadataProviderException {
        return getBinding(SAMLUtil.getBindingForEndpoint(endpoint));
    }

    /**
     * Finds binding with the given name.
     *
     * @param bindingName name
     * @return binding
     * @throws SAMLException in case binding can't be found
     */
    protected SAMLBinding getBinding(String bindingName) throws SAMLException {
        for (SAMLBinding binding : bindings) {
            if (binding.getBindingURI().equals(bindingName)) {
                return binding;
            }
        }
        throw new SAMLException("Binding " + bindingName + " is not available, please check your configuration");
    }

}