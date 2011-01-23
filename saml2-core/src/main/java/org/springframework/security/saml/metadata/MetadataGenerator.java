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
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.*;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.key.KeyManager;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;

/**
 * The class is responsible for generation of service provider metadata describing the application in
 * current deployment environment. All the URLs in the metadata will be derived from information in
 * the ServletContext.
 *
 * @author Vladimir Schäfer
 */
public class MetadataGenerator implements ApplicationContextAware {

    private String entityPath;

    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private boolean signMetadata = true;

    private Collection<String> nameID = null;
    private Collection<String> bindings = null;

    private static final Collection<String> defaultNameID = Arrays.asList(NameIDType.EMAIL,
            NameIDType.TRANSIENT,
            NameIDType.PERSISTENT,
            NameIDType.UNSPECIFIED,
            NameIDType.X509_SUBJECT);

    private static final Collection<String> defaultBindings = Arrays.asList(SAMLConstants.SAML2_POST_BINDING_URI,
            SAMLConstants.SAML2_ARTIFACT_BINDING_URI,
            SAMLConstants.SAML2_REDIRECT_BINDING_URI,
            SAMLConstants.SAML2_SOAP11_BINDING_URI);

    private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    private ApplicationContext applicationContext;

    @Autowired
    private KeyManager keyManager;

    private final Log logger = LogFactory.getLog(MetadataGenerator.class);

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    protected KeyInfo getServerKeyInfo() {
        try {
            NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
            Credential serverCredential = keyManager.getSPSigningCredential();
            return manager.getDefaultManager().getFactory(serverCredential).newInstance().generate(serverCredential);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.error("Can't obtain key from keystore or generate key info", e);
            throw new SAMLRuntimeException("Can't obtain key from keystore or generate key info", e);
        }
    }

    public EntityDescriptor generateMetadata() {

        boolean requestSigned = isRequestSigned();
        boolean assertionSigned = isWantAssertionSigned();
        boolean signMetadata = isSignMetadata();
        Collection<String> includedBindings = getBindings();
        Collection<String> includedNameID = getNameID();
        String entityID = getEntityPath();

        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        descriptor.setEntityID(entityID);
        descriptor.getRoleDescriptors().add(buildSPSSODescriptor(entityID, requestSigned, assertionSigned, includedBindings, includedNameID));

        if (signMetadata) {
            try {
                signSAMLObject(descriptor, keyManager.getSPSigningCredential());
            } catch (MessageEncodingException e) {
                throw new RuntimeException(e);
            }
        }

        return descriptor;

    }

    protected SPSSODescriptor buildSPSSODescriptor(String entityID, boolean requestSigned, boolean wantAssertionSigned, Collection<String> includedBindings, Collection<String> includedNameID) {

        SAMLObjectBuilder<SPSSODescriptor> builder = (SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        SPSSODescriptor spDescriptor = builder.buildObject();
        spDescriptor.setAuthnRequestsSigned(requestSigned);
        spDescriptor.setWantAssertionsSigned(wantAssertionSigned);
        spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Name ID
        spDescriptor.getNameIDFormats().addAll(getNameIDFormat(includedNameID));

        // Populate bindings
        int index = 0;
        boolean isDefault = true;
        if (includedBindings.contains(SAMLConstants.SAML2_POST_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(entityID, isDefault, index, SAMLConstants.SAML2_POST_BINDING_URI));
            spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(entityID, SAMLConstants.SAML2_POST_BINDING_URI));
            index++;
            isDefault = false;
        }
        if (includedBindings.contains(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
            spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(entityID, isDefault, index, SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
            index++;
            isDefault = false;
        }
        if (includedBindings.contains(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
            spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(entityID, SAMLConstants.SAML2_REDIRECT_BINDING_URI));
        }
        if (includedBindings.contains(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
            spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(entityID, SAMLConstants.SAML2_SOAP11_BINDING_URI));
        }

        // Generate key info
        spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo()));
        spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.ENCRYPTION, getServerKeyInfo()));

        return spDescriptor;

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

    protected AssertionConsumerService getAssertionConsumerService(String entityID, boolean isDefault, int index, String binding) {
        SAMLObjectBuilder<AssertionConsumerService> builder = (SAMLObjectBuilder<AssertionConsumerService>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        AssertionConsumerService consumer = builder.buildObject();
        SAMLProcessingFilter samlFilter = getSAMLFilter();
        consumer.setLocation(getServerURL(entityID, samlFilter.getFilterProcessesUrl()));
        consumer.setBinding(binding);
        consumer.setIsDefault(isDefault);
        consumer.setIndex(index);
        return consumer;
    }

    protected SingleLogoutService getSingleLogoutService(String entityID, String binding) {
        SAMLObjectBuilder<SingleLogoutService> builder = (SAMLObjectBuilder<SingleLogoutService>) builderFactory.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        SingleLogoutService logoutService = builder.buildObject();
        SAMLLogoutProcessingFilter logoutFilter = getSAMLLogoutFilter();
        logoutService.setLocation(getServerURL(entityID, logoutFilter.getFilterProcessesUrl()));
        logoutService.setBinding(binding);
        return logoutService;
    }

    /**
     * Creates URL at which the local server is capable of accepting incoming SAML messages.
     *
     * @param entityID entity ID
     * @param processingURL local context at which processing filter is waiting
     * @return URL of local server
     */
    private String getServerURL(String entityID, String processingURL) {
        StringBuffer result = new StringBuffer();
        if (!processingURL.startsWith("/")) {
            processingURL = "/" + processingURL;
        }
        result.append(entityID).append(processingURL);
        return result.toString();
    }

    private SAMLProcessingFilter getSAMLFilter() {
        Map map = applicationContext.getBeansOfType(SAMLProcessingFilter.class);
        if (map.size() == 0) {
            logger.error("No SAML Processing filter was defined");
            throw new SAMLRuntimeException("No SAML processing filter is defined in Spring configuration");
        } else if (map.size() > 1) {
            logger.error("More then one SAML Processing filter were defined");
            throw new SAMLRuntimeException("More then one SAML processing filter were defined in Spring configuration");
        } else {
            return (SAMLProcessingFilter) map.values().iterator().next();
        }
    }

    private SAMLLogoutProcessingFilter getSAMLLogoutFilter() {
        Map map = applicationContext.getBeansOfType(SAMLLogoutProcessingFilter.class);
        if (map.size() == 0) {
            logger.error("No SAML Processing filter was defined");
            throw new SAMLRuntimeException("No SAML processing filter is defined in Spring configuration");
        } else if (map.size() > 1) {
            logger.error("More then one SAML Processing filter were defined");
            throw new SAMLRuntimeException("More then one SAML processing filter were defined in Spring configuration");
        } else {
            return (SAMLLogoutProcessingFilter) map.values().iterator().next();
        }
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
                //TODO pull SecurityConfiguration from SAMLMessageContext?  needs to be added
                //TODO pull binding-specific keyInfoGenName from encoder setting, etc?
                SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
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

    public Collection<String> getBindings() {
        return bindings == null ? defaultBindings : bindings;
    }

    public void setBindings(Collection<String> bindings) {
        this.bindings = bindings;
    }

    public String getEntityPath() {
        return entityPath;
    }

    public void setEntityPath(String entityPath) {
        this.entityPath = entityPath;
    }

    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

}