/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.serviceprovider.bean;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.ServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.spi.ServiceProviderSamlValidator;
import org.springframework.security.saml.serviceprovider.spi.SingletonServiceProviderConfigurationResolver;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.util.Assert;

@Configuration
public class SamlServiceProviderBeanConfiguration {

	private final SamlTransformer transformer;
	private final HostedServiceProviderConfiguration configuration;

	public SamlServiceProviderBeanConfiguration(
		@Autowired SamlTransformer transformer,
		@Autowired(required = false) HostedServiceProviderConfiguration configuration) {
		this.transformer = transformer;
		this.configuration = configuration;
	}

	@Bean(name = "samlServiceProviderValidator")
	public SamlValidator samlValidator() {
		return new ServiceProviderSamlValidator(transformer);
	}

	@Bean(name = "samlServiceProviderMetadataResolver")
	public ServiceProviderMetadataResolver serviceProviderMetadataResolver() {
		return new DefaultServiceProviderMetadataResolver(transformer);
	}

	@Bean(name = "samlServiceProviderResolver")
	public ServiceProviderResolver serviceProviderResolver() {
		return new DefaultServiceProviderResolver(
			serviceProviderMetadataResolver(),
			serviceProviderConfigurationResolver()
		);
	}

	@Bean(name = "samlServiceProviderTemplateEngine")
	public SamlTemplateEngine samlTemplateEngine() {
		return new VelocityTemplateEngine(true);
	}

	@Bean(name = "samlServiceProviderConfigurationResolver")
	public ServiceProviderConfigurationResolver serviceProviderConfigurationResolver() {
		Assert.notNull(
			configuration,
			"Unable to configure a " + ServiceProviderConfigurationResolver.class.getName() +
				" instance, without an actual configuration. " +
				"Either expose a " + HostedServiceProviderConfiguration.class.getName() +
				"bean or override the " + ServiceProviderConfigurationResolver.class.getName() +
				" bean."
		);
		return new SingletonServiceProviderConfigurationResolver(configuration);
	}

}
