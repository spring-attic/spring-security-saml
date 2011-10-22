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
package org.springframework.security.saml.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.*;
import org.opensaml.samlext.idpdisco.DiscoveryResponse;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.key.KeyManager;

import javax.xml.namespace.QName;
import java.util.*;

/**
 * The class is responsible for generation of service provider metadata describing the application in
 * the current deployment environment. All the URLs in the metadata will be derived from information in
 * the ServletContext.
 *
 * @author Vladimir Schäfer
 */
public class MetadataGenerator {

    private String entityId;
    private String entityBaseURL;
    private String entityAlias;

    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private boolean signMetadata = true;

    private String signingKey = null;
    private String encryptionKey = null;
    private String tlsKey = null;

    private int assertionConsumerIndex = 0;

    private Collection<String> bindingsSSO = Arrays.asList(SAMLConstants.SAML2_POST_BINDING_URI, SAMLConstants.SAML2_PAOS_BINDING_URI, SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
    private Collection<String> bindingsHoKSSO = Arrays.asList(SAMLConstants.SAML2_POST_BINDING_URI, SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
    private Collection<String> bindingsSLO = Arrays.asList(SAMLConstants.SAML2_POST_BINDING_URI, SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_SOAP11_BINDING_URI);

    private boolean includeDiscovery = true;
    private String customDiscoveryURL;

    private Collection<String> nameID = null;
    public static final Collection<String> defaultNameID = Arrays.asList(NameIDType.EMAIL,
            NameIDType.TRANSIENT,
            NameIDType.PERSISTENT,
            NameIDType.UNSPECIFIED,
            NameIDType.X509_SUBJECT);

    protected XMLObjectBuilderFactory builderFactory;

    protected KeyManager keyManager;

    private final Log logger = LogFactory.getLog(MetadataGenerator.class);

    /**
     * Default constructor.
     */
    public MetadataGenerator() {
        this.builderFactory = Configuration.getBuilderFactory();
    }

    protected KeyInfo getServerKeyInfo(String alias) {
        Credential serverCredential = keyManager.getCredential(alias);
        if (serverCredential == null) {
            throw new RuntimeException("Key for alias " + alias + " not found");
        } else if (serverCredential.getPrivateKey() == null) {
            throw new RuntimeException("Key with alias " + alias + " doesn't have a private key");
        }
        return generateKeyInfoForCredential(serverCredential);
    }

    protected KeyInfo generateKeyInfoForCredential(Credential credential) {
        try {
            NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
            SecurityHelper.getKeyInfoGenerator(credential, null, getKeyInfoGeneratorName());
            KeyInfoGeneratorFactory factory = manager.getDefaultManager().getFactory(credential);
            return factory.newInstance().generate(credential);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.error("Can't obtain key from the keystore or generate key info: " + encryptionKey, e);
            throw new SAMLRuntimeException("Can't obtain key from keystore or generate key info", e);
        }
    }

    public void generateExtendedMetadata(ExtendedMetadata metadata) {
        metadata.setEcpEnabled(false);
        metadata.setIdpDiscoveryEnabled(true);
        metadata.setEncryptionKey(encryptionKey);
        metadata.setSigningKey(signingKey);
        metadata.setAlias(entityAlias);
        metadata.setTlsKey(tlsKey);
        metadata.setLocal(true);
    }

    public EntityDescriptor generateMetadata() {

        if (signingKey == null) {
            signingKey = keyManager.getDefaultCredentialName();
        }
        if (encryptionKey == null) {
            encryptionKey = keyManager.getDefaultCredentialName();
        }
        if (tlsKey == null) {
            tlsKey = keyManager.getDefaultCredentialName();
        }

        boolean requestSigned = isRequestSigned();
        boolean assertionSigned = isWantAssertionSigned();
        boolean signMetadata = isSignMetadata();

        Collection<String> includedNameID = getNameID();

        String entityId = getEntityId();
        String entityBaseURL = getEntityBaseURL();
        String entityAlias = getEntityAlias();

        if (entityId == null || entityBaseURL == null) {
            throw new RuntimeException("Required attributes weren't set");
        }

        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        descriptor.setEntityID(entityId);
        descriptor.getRoleDescriptors().add(buildSPSSODescriptor(entityBaseURL, entityAlias, requestSigned, assertionSigned, includedNameID));

        if (signMetadata) {
            try {
                signSAMLObject(descriptor, keyManager.getCredential(signingKey));
            } catch (MessageEncodingException e) {
                throw new RuntimeException(e);
            }
        }

        return descriptor;

    }

    protected SPSSODescriptor buildSPSSODescriptor(String entityBaseURL, String entityAlias, boolean requestSigned, boolean wantAssertionSigned, Collection<String> includedNameID) {

        SAMLObjectBuilder<SPSSODescriptor> builder = (SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        SPSSODescriptor spDescriptor = builder.buildObject();
        spDescriptor.setAuthnRequestsSigned(requestSigned);
        spDescriptor.setWantAssertionsSigned(wantAssertionSigned);
        spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Name ID
        spDescriptor.getNameIDFormats().addAll(getNameIDFormat(includedNameID));

        // Populate endpoints
        int index = 0;

        // Assertion consumer MUST NOT be used with HTTP Redirect, Profiles 424, same applies to HoK profile
        if (bindingsSSO.contains(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(entityBaseURL, entityAlias, assertionConsumerIndex == index, index++, getSAMLWebSSOProcessingFilterPath(), SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
        }
        if (bindingsSSO.contains(SAMLConstants.SAML2_POST_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(entityBaseURL, entityAlias, assertionConsumerIndex == index, index++, getSAMLWebSSOProcessingFilterPath(), SAMLConstants.SAML2_POST_BINDING_URI));
        }
        if (bindingsSSO.contains(SAMLConstants.SAML2_PAOS_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(entityBaseURL, entityAlias, assertionConsumerIndex == index, index++, getSAMLWebSSOProcessingFilterPath(), SAMLConstants.SAML2_PAOS_BINDING_URI));
        }
        if (bindingsHoKSSO.contains(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getHoKAssertionConsumerService(entityBaseURL, entityAlias, assertionConsumerIndex == index, index++, getSAMLWebSSOHoKProcessingFilterPath(), SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
        }
        if (bindingsHoKSSO.contains(SAMLConstants.SAML2_POST_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getHoKAssertionConsumerService(entityBaseURL, entityAlias, assertionConsumerIndex == index, index++, getSAMLWebSSOHoKProcessingFilterPath(), SAMLConstants.SAML2_POST_BINDING_URI));
        }

        if (bindingsSLO.contains(SAMLConstants.SAML2_POST_BINDING_URI)) {
            spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(entityBaseURL, entityAlias, SAMLConstants.SAML2_POST_BINDING_URI));
        }
        if (bindingsSLO.contains(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
            spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(entityBaseURL, entityAlias, SAMLConstants.SAML2_REDIRECT_BINDING_URI));
        }
        if (bindingsSLO.contains(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
            spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(entityBaseURL, entityAlias, SAMLConstants.SAML2_SOAP11_BINDING_URI));
        }

        // Build extensions
        Extensions extensions = buildExtensions(entityBaseURL, entityAlias);
        if (extensions != null) {
            spDescriptor.setExtensions(extensions);
        }

        // Generate key info
        spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo(signingKey)));
        spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.ENCRYPTION, getServerKeyInfo(encryptionKey)));

        // Include TLS key with unspecified usage in case it differs from the singing and encryption keys
        if (tlsKey != null && !(tlsKey.equals(encryptionKey)) && !(tlsKey.equals(signingKey))) {
            spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.UNSPECIFIED, getServerKeyInfo(tlsKey)));
        }

        return spDescriptor;

    }

    protected Extensions buildExtensions(String entityBaseURL, String entityURL) {

        boolean include = false;
        Extensions extensions = new ExtensionsBuilder().buildObject();

        // Add discovery
        if (isIncludeDiscovery()) {
            DiscoveryResponse discoveryService = getDiscoveryService(entityBaseURL, entityURL);
            extensions.getUnknownXMLObjects().add(discoveryService);
            include = true;
        }

        if (include) {
            return extensions;
        } else {
            return null;
        }

    }

    protected KeyDescriptor getKeyDescriptor(UsageType type, KeyInfo key) {
        SAMLObjectBuilder<KeyDescriptor> builder = (SAMLObjectBuilder<KeyDescriptor>) Configuration.getBuilderFactory().getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyDescriptor descriptor = builder.buildObject();
        descriptor.setUse(type);
        descriptor.setKeyInfo(key);
        return descriptor;
    }

    protected Collection<NameIDFormat> getNameIDFormat(Collection<String> includedNameID) {
        Collection<NameIDFormat> formats = new LinkedList<NameIDFormat>();

        SAMLObjectBuilder<NameIDFormat> builder = (SAMLObjectBuilder<NameIDFormat>) builderFactory.getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
        NameIDFormat nameID;

        if (includedNameID.contains(NameIDType.EMAIL)) {
            nameID = builder.buildObject();
            nameID.setFormat(NameIDType.EMAIL);
            formats.add(nameID);
        }

        if (includedNameID.contains(NameIDType.TRANSIENT)) {
            nameID = builder.buildObject();
            nameID.setFormat(NameIDType.TRANSIENT);
            formats.add(nameID);
        }

        if (includedNameID.contains(NameIDType.PERSISTENT)) {
            nameID = builder.buildObject();
            nameID.setFormat(NameIDType.PERSISTENT);
            formats.add(nameID);
        }

        if (includedNameID.contains(NameIDType.UNSPECIFIED)) {
            nameID = builder.buildObject();
            nameID.setFormat(NameIDType.UNSPECIFIED);
            formats.add(nameID);
        }

        if (includedNameID.contains(NameIDType.X509_SUBJECT)) {
            nameID = builder.buildObject();
            nameID.setFormat(NameIDType.X509_SUBJECT);
            formats.add(nameID);
        }

        return formats;
    }

    protected AssertionConsumerService getAssertionConsumerService(String entityBaseURL, String entityAlias, boolean isDefault, int index, String filterURL, String binding) {
        SAMLObjectBuilder<AssertionConsumerService> builder = (SAMLObjectBuilder<AssertionConsumerService>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        AssertionConsumerService consumer = builder.buildObject();
        consumer.setLocation(getServerURL(entityBaseURL, entityAlias, filterURL));
        consumer.setBinding(binding);
        if (isDefault) {
            consumer.setIsDefault(true);
        }
        consumer.setIndex(index);
        return consumer;
    }

    protected AssertionConsumerService getHoKAssertionConsumerService(String entityBaseURL, String entityAlias, boolean isDefault, int index, String filterURL, String binding) {
        AssertionConsumerService hokAssertionConsumer = getAssertionConsumerService(entityBaseURL, entityAlias, isDefault, index, filterURL, org.springframework.security.saml.SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI);
        QName consumerName = new QName(org.springframework.security.saml.SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI, AuthnRequest.PROTOCOL_BINDING_ATTRIB_NAME, "hoksso");
        hokAssertionConsumer.getUnknownAttributes().put(consumerName, binding);
        return hokAssertionConsumer;
    }

    protected DiscoveryResponse getDiscoveryService(String entityBaseURL, String entityAlias) {
        SAMLObjectBuilder<DiscoveryResponse> builder = (SAMLObjectBuilder<DiscoveryResponse>) builderFactory.getBuilder(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
        DiscoveryResponse discovery = builder.buildObject(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
        discovery.setBinding(DiscoveryResponse.IDP_DISCO_NS);
        Map<String, String> params = new HashMap<String, String>();
        params.put(SAMLEntryPoint.DISCOVERY_RESPONSE_PARAMETER, "true");
        if (customDiscoveryURL != null && customDiscoveryURL.length() > 0) {
            discovery.setLocation(customDiscoveryURL);
        } else {
            discovery.setLocation(getServerURL(entityBaseURL, entityAlias, getSAMLEntryPointPath(), params));
        }
        return discovery;
    }

    protected SingleLogoutService getSingleLogoutService(String entityBaseURL, String entityAlias, String binding) {
        SAMLObjectBuilder<SingleLogoutService> builder = (SAMLObjectBuilder<SingleLogoutService>) builderFactory.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        SingleLogoutService logoutService = builder.buildObject();
        logoutService.setLocation(getServerURL(entityBaseURL, entityAlias, getSAMLLogoutFilterPath()));
        logoutService.setBinding(binding);
        return logoutService;
    }

    /**
     * Creates URL at which the local server is capable of accepting incoming SAML messages.
     *
     * @param entityBaseURL entity ID
     * @param processingURL local context at which processing filter is waiting
     * @return URL of local server
     */
    private String getServerURL(String entityBaseURL, String entityAlias, String processingURL) {

        return getServerURL(entityBaseURL, entityAlias, processingURL, null);

    }

    /**
     * Creates URL at which the local server is capable of accepting incoming SAML messages.
     *
     * @param entityBaseURL entity ID
     * @param processingURL local context at which processing filter is waiting
     * @param parameters    key - value pairs to be included as query part of the generated url, can be null
     * @return URL of local server
     */
    private String getServerURL(String entityBaseURL, String entityAlias, String processingURL, Map<String, String> parameters) {

        StringBuffer result = new StringBuffer();
        result.append(entityBaseURL);
        if (!processingURL.startsWith("/")) {
            result.append("/");
        }
        result.append(processingURL);
        if (!processingURL.endsWith("/")) {
            result.append("/");
        }
        if (entityAlias != null) {
            result.append("alias/");
            result.append(entityAlias);
        }

        String resultString = result.toString();

        if (parameters == null || parameters.size() == 0) {

            return resultString;

        } else {

            // Add parameters
            URLBuilder returnUrlBuilder = new URLBuilder(resultString);
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                returnUrlBuilder.getQueryParams().add(new Pair<String, String>(entry.getKey(), entry.getValue()));
            }
            return returnUrlBuilder.buildURL();

        }

    }

    private String getSAMLWebSSOProcessingFilterPath() {
        return SAMLProcessingFilter.FILTER_URL;
    }

    private String getSAMLWebSSOHoKProcessingFilterPath() {
        return SAMLWebSSOHoKProcessingFilter.WEBSSO_HOK_URL;
    }

    private String getSAMLEntryPointPath() {
        return SAMLEntryPoint.FILTER_URL;
    }

    private String getSAMLLogoutFilterPath() {
        return SAMLLogoutProcessingFilter.FILTER_URL;
    }

    /**
     * Signs the given SAML message if it a {@link org.opensaml.common.SignableSAMLObject} and this encoder has signing credentials.
     *
     * @param outboundSAML      message to sign
     * @param signingCredential credential to sign with
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException
     *          thrown if there is a problem marshalling or signing the outbound message
     */
    @SuppressWarnings("unchecked")
    protected void signSAMLObject(SAMLObject outboundSAML, Credential signingCredential) throws MessageEncodingException {

        if (outboundSAML instanceof SignableSAMLObject && signingCredential != null) {
            SignableSAMLObject signableMessage = (SignableSAMLObject) outboundSAML;

            XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(
                    Signature.DEFAULT_ELEMENT_NAME);
            Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

            signature.setSigningCredential(signingCredential);
            try {
                SecurityHelper.prepareSignatureParams(signature, signingCredential, null, getKeyInfoGeneratorName());
            } catch (org.opensaml.xml.security.SecurityException e) {
                throw new MessageEncodingException("Error preparing signature for signing", e);
            }

            signableMessage.setSignature(signature);

            try {
                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableMessage);
                if (marshaller == null) {
                    throw new MessageEncodingException("No marshaller registered for "
                            + signableMessage.getElementQName() + ", unable to marshall in preperation for signing");
                }
                marshaller.marshall(signableMessage);

                Signer.signObject(signature);
            } catch (MarshallingException e) {
                logger.error("Unable to marshall protocol message in preparation for signing", e);
                throw new MessageEncodingException("Unable to marshall protocol message in preparation for signing", e);
            } catch (SignatureException e) {
                logger.error("Unable to sign protocol message", e);
                throw new MessageEncodingException("Unable to sign protocol message", e);
            }
        }
    }

    /**
     * Name of the KeyInfoGenerator registered at default KeyInfoGeneratorManager.
     *
     * @return key info generator name
     * @see Configuration#getGlobalSecurityConfiguration().getKeyInfoGeneratorManager()
     */
    protected String getKeyInfoGeneratorName() {
        return org.springframework.security.saml.SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR;
    }

    public boolean isRequestSigned() {
        return requestSigned;
    }

    public void setRequestSigned(boolean requestSigned) {
        this.requestSigned = requestSigned;
    }

    public boolean isWantAssertionSigned() {
        return wantAssertionSigned;
    }

    public void setWantAssertionSigned(boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
    }

    public boolean isSignMetadata() {
        return signMetadata;
    }

    public void setSignMetadata(boolean signMetadata) {
        this.signMetadata = signMetadata;
    }

    public Collection<String> getNameID() {
        return nameID == null ? defaultNameID : nameID;
    }

    public void setNameID(Collection<String> nameID) {
        this.nameID = nameID;
    }

    public String getEntityBaseURL() {
        return entityBaseURL;
    }

    public String getEntityAlias() {
        return entityAlias;
    }

    public void setEntityAlias(String entityAlias) {
        this.entityAlias = entityAlias;
    }

    public void setEntityBaseURL(String entityBaseURL) {
        this.entityBaseURL = entityBaseURL;
    }

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }

    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getEntityId() {
        return entityId;
    }

    public String getTlsKey() {
        return tlsKey;
    }

    public void setTlsKey(String tlsKey) {
        this.tlsKey = tlsKey;
    }

    public Collection<String> getBindingsSSO() {
        return bindingsSSO;
    }

    public void setBindingsSSO(Collection<String> bindingsSSO) {
        if (bindingsSSO == null) {
            this.bindingsSSO = Collections.emptySet();
        } else {
            this.bindingsSSO = bindingsSSO;
        }
    }

    public Collection<String> getBindingsSLO() {
        return bindingsSLO;
    }

    public void setBindingsSLO(Collection<String> bindingsSLO) {
        if (bindingsSLO == null) {
            this.bindingsSLO = Collections.emptySet();
        } else {
            this.bindingsSLO = bindingsSLO;
        }
    }

    public Collection<String> getBindingsHoKSSO() {
        return bindingsHoKSSO;
    }

    public void setBindingsHoKSSO(Collection<String> bindingsHoKSSO) {
        if (bindingsHoKSSO == null) {
            this.bindingsHoKSSO = Collections.emptySet();
        } else {
            this.bindingsHoKSSO = bindingsHoKSSO;
        }
    }

    public boolean isIncludeDiscovery() {
        return includeDiscovery;
    }

    /**
     * When true discovery profile metadata pointing to the default SAMLEntryPoint will be generated.
     *
     * @param includeDiscovery discovery
     */
    public void setIncludeDiscovery(boolean includeDiscovery) {
        this.includeDiscovery = includeDiscovery;
    }

    public int getAssertionConsumerIndex() {
        return assertionConsumerIndex;
    }

    public void setAssertionConsumerIndex(int assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
    }

    public String getCustomDiscoveryURL() {
        return customDiscoveryURL;
    }

    public void setCustomDiscoveryURL(String customDiscoveryURL) {
        this.customDiscoveryURL = customDiscoveryURL;
    }
}