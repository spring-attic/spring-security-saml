/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml2.serviceprovider.bean;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.serviceprovider.web.WebServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderConfigurationResolver;
import org.springframework.security.saml2.serviceprovider.web.configuration.SingletonServiceProviderConfigurationResolver;
import org.springframework.security.saml2.serviceprovider.metadata.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.metadata.Saml2ServiceProviderMetadataResolver;
import org.springframework.security.saml2.provider.validation.DefaultSaml2ServiceProviderValidator;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.util.Assert;

@Configuration
public class SamlServiceProviderBeans {

	private final Saml2Transformer transformer;
	private final HostedSaml2ServiceProviderConfiguration configuration;

	public SamlServiceProviderBeans(
		@Autowired Saml2Transformer transformer,
		@Autowired(required = false) HostedSaml2ServiceProviderConfiguration configuration) {
		this.transformer = transformer;
		this.configuration = configuration;
	}

	@Bean(name = "samlServiceProviderValidator")
	public Saml2ServiceProviderValidator samlValidator() {
		return new DefaultSaml2ServiceProviderValidator(transformer);
	}

	@Bean(name = "samlServiceProviderMetadataResolver")
	public Saml2ServiceProviderMetadataResolver serviceProviderMetadataResolver() {
		return new DefaultServiceProviderMetadataResolver(transformer);
	}

	@Bean(name = "samlServiceProviderResolver")
	public Saml2ServiceProviderResolver serviceProviderResolver() {
		return new WebServiceProviderResolver(
			serviceProviderMetadataResolver(),
			serviceProviderConfigurationResolver()
		);
	}

	@Bean(name = "samlServiceProviderConfigurationResolver")
	public Saml2ServiceProviderConfigurationResolver serviceProviderConfigurationResolver() {
		Assert.notNull(
			configuration,
			"Unable to configure a " + Saml2ServiceProviderConfigurationResolver.class.getName() +
				" instance, without an actual configuration. " +
				"Either expose a " + HostedSaml2ServiceProviderConfiguration.class.getName() +
				"bean or override the " + Saml2ServiceProviderConfigurationResolver.class.getName() +
				" bean."
		);
		return SingletonServiceProviderConfigurationResolver.fromConfiguration(configuration);
	}

}
