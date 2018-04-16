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

package org.springframework.security.saml2.init;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.springframework.security.saml2.metadata.Endpoint;
import org.springframework.security.saml2.metadata.NameID;
import org.springframework.security.saml2.util.InMemoryKeyStore;
import org.springframework.security.saml2.xml.SimpleKey;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

public class OpenSamlConfiguration extends SpringSecuritySaml {

    private BasicParserPool parserPool;

    public OpenSamlConfiguration() {
        this.parserPool = new BasicParserPool();
    }

    public BasicParserPool getParserPool() {
        return parserPool;
    }

    void bootstrap() {
        //configure default values
        //maxPoolSize = 5;
        parserPool.setMaxPoolSize(50);
        //coalescing = true;
        parserPool.setCoalescing(true);
        //expandEntityReferences = false;
        parserPool.setExpandEntityReferences(false);
        //ignoreComments = true;
        parserPool.setIgnoreComments(true);
        //ignoreElementContentWhitespace = true;
        parserPool.setIgnoreElementContentWhitespace(true);
        //namespaceAware = true;
        parserPool.setNamespaceAware(true);
        //schema = null;
        parserPool.setSchema(null);
        //dtdValidating = false;
        parserPool.setDTDValidating(false);
        //xincludeAware = false;
        parserPool.setXincludeAware(false);

        Map<String, Object> builderAttributes = new HashMap<>();
        parserPool.setBuilderAttributes(builderAttributes);

        Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
        parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
        parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
        parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
        parserBuilderFeatures.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
        parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
        parserPool.setBuilderFeatures(parserBuilderFeatures);

        try {
            parserPool.initialize();
        } catch (ComponentInitializationException x) {
            throw new RuntimeException("Unable to initialize OpenSaml v3 ParserPool", x);
        }


        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Unable to initialize OpenSaml v3", e);
        }

        XMLObjectProviderRegistry registry;
        synchronized (ConfigurationService.class) {
            registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
            if (registry == null) {
                registry = new XMLObjectProviderRegistry();
                ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
            }
        }

        registry.setParserPool(parserPool);
    }


    public XMLObjectBuilderFactory getBuilderFactory() {
        return XMLObjectProviderRegistrySupport.getBuilderFactory();
    }

    public MarshallerFactory getMarshallerFactory() {
        return XMLObjectProviderRegistrySupport.getMarshallerFactory();
    }

    public UnmarshallerFactory getUnmarshallerFactory() {
        return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    }

    public EntityDescriptor getEntityDescriptor() {
        XMLObjectBuilderFactory builderFactory = getBuilderFactory();
        SAMLObjectBuilder<EntityDescriptor > builder =
            (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public SPSSODescriptor getSPSSODescriptor() {
        SAMLObjectBuilder<SPSSODescriptor> builder =
            (SAMLObjectBuilder<SPSSODescriptor>) getBuilderFactory().getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public Extensions getMetadataExtensions() {
        SAMLObjectBuilder<Extensions> builder =
            (SAMLObjectBuilder<Extensions>) getBuilderFactory().getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public NameIDFormat getNameIDFormat(NameID nameID) {
        SAMLObjectBuilder<NameIDFormat> builder =
            (SAMLObjectBuilder<NameIDFormat>) getBuilderFactory().getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
        NameIDFormat format = builder.buildObject();
        format.setFormat(nameID.toString());
        return format;
    }

    public AssertionConsumerService getAssertionConsumerService(Endpoint endpoint, int index) {
        SAMLObjectBuilder<AssertionConsumerService> builder =
            (SAMLObjectBuilder<AssertionConsumerService>) getBuilderFactory().getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        AssertionConsumerService consumer = builder.buildObject();
        consumer.setLocation(endpoint.getLocation());
        consumer.setBinding(endpoint.getBinding().toString());
        consumer.setIsDefault(endpoint.isDefault());
        consumer.setIndex(index);
        return consumer;
    }

    public SingleLogoutService getSingleLogoutService(Endpoint endpoint) {
        SAMLObjectBuilder<SingleLogoutService> builder =
            (SAMLObjectBuilder<SingleLogoutService>) getBuilderFactory().getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        SingleLogoutService service = builder.buildObject();
        service.setBinding(endpoint.getBinding().toString());
        service.setLocation(endpoint.getLocation());
        return service;
    }

    public KeyDescriptor getKeyDescriptor(SimpleKey key) {
        SAMLObjectBuilder<KeyDescriptor> builder =
            (SAMLObjectBuilder<KeyDescriptor>)getBuilderFactory().getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyDescriptor descriptor = builder.buildObject();

        KeyStoreCredentialResolver resolver = getCredentialsResolver(key);
        Credential credential = getCredential(key, resolver);
        try {
            KeyInfo info = getKeyInfoGenerator(credential).generate(credential);
            descriptor.setKeyInfo(info);
            if (key.getType()!=null) {
                descriptor.setUse(UsageType.valueOf(key.getType().toString()));
            }
            return descriptor;
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public Credential getCredential(SimpleKey key, KeyStoreCredentialResolver resolver) {
        try {
            CriteriaSet cs = new CriteriaSet();
            EntityIdCriterion criteria = new EntityIdCriterion(key.getAlias());
            cs.add(criteria);
            X509Credential creds = (X509Credential) resolver.resolveSingle(cs);
            return creds;
        } catch (ResolverException e) {
            throw new RuntimeException("Can't obtain SP private key", e);
        }
    }

    public KeyStoreCredentialResolver getCredentialsResolver(SimpleKey key) {
        InMemoryKeyStore ks = InMemoryKeyStore.fromKey(key);
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(
            ks.getKeyStore(),
            Collections.singletonMap(key.getAlias(), key.getPassphrase())
        );
        return resolver;
    }

    public KeyInfoGenerator getKeyInfoGenerator(Credential credential) {
        NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager();
        return manager.getDefaultManager().getFactory(credential).newInstance();
    }


}
