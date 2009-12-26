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
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.signature.KeyInfo;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Iterator;
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

    private String serverKeyAlias;
    private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    private ApplicationContext applicationContext;
    private CredentialResolver credentialResolver;

    private final Log logger = LogFactory.getLog(this.getClass());

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    protected KeyInfo getServerKeyInfo() {
        try {
            NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
            Credential serverCredential = getServerCredential(serverKeyAlias);
            return manager.getDefaultManager().getFactory(serverCredential).newInstance().generate(serverCredential);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.error("Can't obtain key from keystore or generate key info", e);
            throw new SAMLRuntimeException("Can't obtain key from keystore or generate key info", e);
        }
    }

    private Credential getServerCredential(String entityID) throws org.opensaml.xml.security.SecurityException {
        CriteriaSet cs = new CriteriaSet();
        EntityIDCriteria criteria = new EntityIDCriteria(entityID);
        cs.add(criteria);
        Iterator<Credential> credentialIterator = credentialResolver.resolve(cs).iterator();
        if (credentialIterator.hasNext()) {
            return credentialIterator.next();
        } else {
            logger.error("Key with ID '" + entityID + "' wasn't found in the configured key store");
            throw new SAMLRuntimeException("Key with ID '" + entityID + "' wasn't found in the configured key store");
        }
    }

    public EntityDescriptor generateMetadata(HttpServletRequest request) {
        return generateMetadata(request, true, true);
    }

    public EntityDescriptor generateMetadata(HttpServletRequest request, boolean requestSigned, boolean wantAssertionSigned) {
        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        descriptor.setEntityID(getEntityID(request));
        descriptor.getRoleDescriptors().add(buildSPSSODescriptor(request, requestSigned, wantAssertionSigned));
        return descriptor;
    }

    protected SPSSODescriptor buildSPSSODescriptor(HttpServletRequest request, boolean requestSigned, boolean wantAssertionSigned) {
        SAMLObjectBuilder<SPSSODescriptor> builder = (SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        SPSSODescriptor spDescriptor = builder.buildObject();
        spDescriptor.setAuthnRequestsSigned(requestSigned);
        spDescriptor.setWantAssertionsSigned(wantAssertionSigned);
        spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Name ID
        spDescriptor.getNameIDFormats().addAll(getNameIDFormat());

        // Add POST consumer
        spDescriptor.getAssertionConsumerServices().add(getPOSTConsumerService(request, true, 0));

        // Add POST logout service
        spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(request));

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

    protected Collection<NameIDFormat> getNameIDFormat() {
        Collection<NameIDFormat> formats = new LinkedList<NameIDFormat>();

        SAMLObjectBuilder<NameIDFormat> builder = (SAMLObjectBuilder<NameIDFormat>) builderFactory.getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
        NameIDFormat nameID;

        nameID = builder.buildObject();
        nameID.setFormat(NameIDType.EMAIL);
        formats.add(nameID);

        nameID = builder.buildObject();
        nameID.setFormat(NameIDType.TRANSIENT);
        formats.add(nameID);

        nameID = builder.buildObject();
        nameID.setFormat(NameIDType.PERSISTENT);
        formats.add(nameID);

        nameID = builder.buildObject();
        nameID.setFormat(NameIDType.UNSPECIFIED);
        formats.add(nameID);

        nameID = builder.buildObject();
        nameID.setFormat(NameIDType.X509_SUBJECT);
        formats.add(nameID);

        return formats;
    }

    protected AssertionConsumerService getPOSTConsumerService(HttpServletRequest request, boolean isDefault, int index) {
        SAMLObjectBuilder<AssertionConsumerService> builder = (SAMLObjectBuilder<AssertionConsumerService>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        AssertionConsumerService consumer = builder.buildObject();
        SAMLProcessingFilter samlFilter = getSAMLFilter();
        consumer.setLocation(getServerURL(request, samlFilter.getFilterProcessesUrl()));
        consumer.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        consumer.setIsDefault(isDefault);
        consumer.setIndex(index);
        return consumer;
    }

    protected SingleLogoutService getSingleLogoutService(HttpServletRequest request) {
        SAMLObjectBuilder<SingleLogoutService> builder = (SAMLObjectBuilder<SingleLogoutService>) builderFactory.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        SingleLogoutService logoutService = builder.buildObject();
        SAMLLogoutProcessingFilter logoutFilter = getSAMLLogoutFilter();
        logoutService.setLocation(getServerURL(request, logoutFilter.getFilterProcessesUrl()));
        logoutService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        return logoutService;
    }

    /**
     * Creates URL at which the local server is capable of accepting incoming SAML messages.
     * @param request request parsed for server name, port, protocol and context
     * @param processingURL local context at which processing filter is waiting
     * @return URL of local server
     */
    private String getServerURL(HttpServletRequest request, String processingURL) {
        StringBuffer result = new StringBuffer();
        if (!processingURL.startsWith("/")) {
            processingURL = "/" + processingURL;
        }
        if (request.isSecure()) {
            result.append("https://");
        } else {
            result.append("http://");
        }
        result.append(request.getServerName()).append(":").append(request.getServerPort());
        result.append(request.getContextPath());
        result.append(processingURL);
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

    protected String getEntityID(HttpServletRequest request) {
        StringBuffer sb = new StringBuffer();
        sb.append(request.getScheme()).append("://").append(request.getServerName());
        sb.append(":").append(request.getServerPort()).append(request.getContextPath());
        return sb.toString();
    }

    public void setCredentialResolver(CredentialResolver credentialResolver) {
        this.credentialResolver = credentialResolver;
    }

    /**
     * Alias of key used for signing of service provider SAML messages.
     * @return key alias
     */
    public String getServerKeyAlias() {
        return serverKeyAlias;
    }

    /**
     * Alias in the keystore used for signing of messages sent by this service provider
     * @param serverKeyAlias alias of an entry in the configured key store
     */
    public void setServerKeyAlias(String serverKeyAlias) {
        if (serverKeyAlias == null) {
            throw new IllegalArgumentException("ServerKeyAlias must be set");
        }
        this.serverKeyAlias = serverKeyAlias;
    }
}