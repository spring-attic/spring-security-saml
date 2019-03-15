/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.provider.service.config;

import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.provider.SamlProviderLogoutFilter;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.AbstractSamlServerBeanConfiguration;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlServiceProviderProvisioning;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.SelectIdentityProviderFilter;
import org.springframework.security.saml.provider.service.ServiceProviderMetadataFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.GenericErrorAuthenticationFailureHandler;
import org.springframework.security.saml.provider.service.authentication.SamlAuthenticationResponseFilter;
import org.springframework.security.saml.provider.service.authentication.ServiceProviderLogoutHandler;
import org.springframework.security.saml.provider.service.authentication.SimpleAuthenticationManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public abstract class SamlServiceProviderServerBeanConfiguration
	extends AbstractSamlServerBeanConfiguration<ServiceProviderService> {

	public Filter spMetadataFilter() {
		return new ServiceProviderMetadataFilter(getSamlProvisioning());
	}

	@Override
	@Bean(name = "samlServiceProviderProvisioning")
	public SamlProviderProvisioning<ServiceProviderService> getSamlProvisioning() {
		return new HostBasedSamlServiceProviderProvisioning(
			samlConfigurationRepository(),
			samlTransformer(),
			samlValidator(),
			samlMetadataCache()
		);
	}

	public Filter spAuthenticationRequestFilter() {
		return new SamlAuthenticationRequestFilter(getSamlProvisioning());
	}

	public Filter spAuthenticationResponseFilter() {
		SamlAuthenticationResponseFilter authenticationFilter =
			new SamlAuthenticationResponseFilter(getSamlProvisioning());
		authenticationFilter.setAuthenticationManager(new SimpleAuthenticationManager());
		authenticationFilter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
		authenticationFilter.setAuthenticationFailureHandler(new GenericErrorAuthenticationFailureHandler());
		return authenticationFilter;
	}

	public Filter spSamlLogoutFilter() {
		return new SamlProviderLogoutFilter<>(
			getSamlProvisioning(),
			new ServiceProviderLogoutHandler(getSamlProvisioning()),
			new SimpleUrlLogoutSuccessHandler(),
			new SecurityContextLogoutHandler()
		);
	}

	public Filter spSelectIdentityProviderFilter() {
		return new SelectIdentityProviderFilter(getSamlProvisioning());
	}

	@Override
	@Bean(name = "spSamlServerConfiguration")
	protected abstract SamlServerConfiguration getDefaultHostSamlServerConfiguration();
}
