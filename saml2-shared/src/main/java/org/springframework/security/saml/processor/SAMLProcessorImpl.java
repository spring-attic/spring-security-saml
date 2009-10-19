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

import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.credential.ChainingCredentialResolver;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.provider.DSAKeyValueProvider;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

/**
 * Processor is capable of parsing SAML message from HttpServletRequest and populate the BasicSAMLMessageContext
 * for further validations.
 *
 * @author Vladimir Schäfer
 */
public class SAMLProcessorImpl implements SAMLProcessor {

    private CredentialResolver resolver;
    private MetadataManager metadata;
    private ParserPool parser;

    public SAMLProcessorImpl(MetadataManager metadata) {
        this.metadata = metadata;
    }

    public void setResolver(CredentialResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Processes the SSO response or IDP initialized SSO and creates SAMLMessageContext object with the
     * unmarshalled response.
     *
     * @param request request
     * @return SAML message context with filled information about the message
     * @throws org.opensaml.common.SAMLException
     *          error retreiving the message from the request
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException
     *          error retreiving metadat
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException
     *          error decoding the message
     * @throws org.opensaml.xml.security.SecurityException
     *          error verifying message
     */
    public BasicSAMLMessageContext processSSO(HttpServletRequest request) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException {

        BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> samlContext = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
        samlContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        samlContext.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        samlContext.setMetadataProvider(metadata);
        samlContext.setLocalEntityId(metadata.getHostedSPName());
        samlContext.setLocalEntityRoleMetadata(metadata.getRole(metadata.getHostedSPName(), SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        samlContext.setLocalEntityMetadata(metadata.getEntityDescriptor(metadata.getHostedSPName()));
        samlContext.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        ChainingCredentialResolver chainedResolver = new ChainingCredentialResolver();
        chainedResolver.getResolverChain().add(new MetadataCredentialResolver(metadata));
        chainedResolver.getResolverChain().add(resolver);

        KeyInfoCredentialResolver keyInfoCredResolver = Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(chainedResolver, keyInfoCredResolver);
        SAMLProtocolMessageXMLSignatureSecurityPolicyRule signatureRule = new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(trustEngine);

        SecurityPolicy policy = new BasicSecurityPolicy();
        policy.getPolicyRules().add(signatureRule);
        StaticSecurityPolicyResolver resolver = new StaticSecurityPolicyResolver(policy);
        samlContext.setSecurityPolicyResolver(resolver);
        samlContext.setInboundSAMLProtocol("urn:oasis:names:tc:SAML:2.0:protocol");

        getDecoder(request, samlContext).decode(samlContext);
        samlContext.setPeerEntityId(samlContext.getPeerEntityMetadata().getEntityID());

        return samlContext;
    }

    /**
     * Analyzes given request and returns a decoder object capable of it's parsing. Currently all requests
     * sent using POST method are presumed to be encoded using SAML2_POST_BINDING, all with get method
     * with SAML2_REDIRECT_BINDING.
     *
     * @param request     request
     * @param samlContext saml context
     * @return decoder
     * @throws SAMLException in case no suitable decoder is found for given request
     */
    protected MessageDecoder getDecoder(HttpServletRequest request, BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> samlContext) throws SAMLException {

        MessageDecoder decoder;
        if (request.getMethod().equals("POST")) {
            samlContext.setCommunicationProfileId(SAMLConstants.SAML2_POST_BINDING_URI);
            decoder = new HTTPPostDecoder(parser);
        } else if (request.getMethod().equals("GET")) {
            samlContext.setCommunicationProfileId(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            decoder = new HTTPRedirectDeflateDecoder(parser);
        } else {
            throw new SAMLException("Unsupported request");
        }

        return decoder;
    }

    /**
     * Setter for the parser pool object
     *
     * @param parser parser pool
     */
    public void setParser(ParserPool parser) {
        this.parser = parser;
    }
}