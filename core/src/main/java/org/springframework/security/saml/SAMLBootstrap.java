/* Copyright 2011 Vladimir Schaefer
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
package org.springframework.security.saml;

import org.opensaml.Configuration;
import org.opensaml.PaosBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

/**
 * Initialization for SAML library. Is automatically called as part of Spring initialization.
 *
 * @author Vladimir Schaefer
 */
public class SAMLBootstrap implements BeanFactoryPostProcessor {

    /**
     * Automatically called to initialize the whole module.
     *
     * @param beanFactory bean factory
     * @throws BeansException errors
     */
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        try {
            PaosBootstrap.bootstrap();
            setMetadataKeyInfoGenerator();
        } catch (ConfigurationException e) {
            throw new FatalBeanException("Error invoking OpenSAML bootstrap", e);
        }
    }

    /**
     * Method registers extension specific KeyInfoGenerator which emits .
     *
     * @see SAMLConstants#SAML_METADATA_KEY_INFO_GENERATOR
     */
    protected void setMetadataKeyInfoGenerator() {
        NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
        generator.setEmitEntityCertificate(true);
        generator.setEmitEntityCertificateChain(true);
        manager.registerFactory(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR, generator);
    }

}