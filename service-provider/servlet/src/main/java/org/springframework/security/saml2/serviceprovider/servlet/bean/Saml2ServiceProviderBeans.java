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

package org.springframework.security.saml2.serviceprovider.servlet.bean;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration;
import org.springframework.security.saml2.provider.validation.DefaultSaml2ServiceProviderValidator;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderRegistrationResolver;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.metadata.Saml2ServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.servlet.registration.DefaultSaml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.servlet.registration.SingletonSaml2ServiceProviderRegistrationResolver;
import org.springframework.security.saml2.serviceprovider.servlet.metadata.DefaultSaml2ServiceProviderMetadataResolver;
import org.springframework.util.Assert;

@Configuration
public class Saml2ServiceProviderBeans {

	private final Saml2Transformer transformer;
	private final HostedSaml2ServiceProviderRegistration registration;

	public Saml2ServiceProviderBeans(
		@Autowired Saml2Transformer transformer,
		@Autowired(required = false) HostedSaml2ServiceProviderRegistration registration) {
		this.transformer = transformer;
		this.registration = registration;
	}

	@Bean(name = "samlServiceProviderValidator")
	public Saml2ServiceProviderValidator samlValidator() {
		return new DefaultSaml2ServiceProviderValidator(transformer);
	}

	@Bean(name = "samlServiceProviderResolver")
	public Saml2ServiceProviderResolver serviceProviderResolver() {
		return new DefaultSaml2ServiceProviderResolver(
			serviceProviderMetadataResolver(),
			serviceProviderRegistrationResolver()
		);
	}

	@Bean(name = "samlServiceProviderMetadataResolver")
	public Saml2ServiceProviderMetadataResolver serviceProviderMetadataResolver() {
		return new DefaultSaml2ServiceProviderMetadataResolver(transformer);
	}

	@Bean(name = "samlServiceProviderRegistrationResolver")
	public Saml2ServiceProviderRegistrationResolver serviceProviderRegistrationResolver() {
		Assert.notNull(
			registration,
			"Unable to configure a " + Saml2ServiceProviderRegistrationResolver.class.getName() +
				" instance, without an actual registration. " +
				"Either expose a " + HostedSaml2ServiceProviderRegistration.class.getName() +
				"bean or override the " + Saml2ServiceProviderRegistrationResolver.class.getName() +
				" bean."
		);
		return SingletonSaml2ServiceProviderRegistrationResolver.fromConfiguration(registration);
	}

}
