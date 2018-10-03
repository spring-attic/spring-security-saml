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

package org.springframework.security.saml.provider.service.config;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.SamlProviderLogoutFilter;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationFilter;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlServiceProviderProvisioning;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.SelectIdentityProviderFilter;
import org.springframework.security.saml.provider.service.ServiceProviderMetadataFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.GenericErrorAuthenticationFailureHandler;
import org.springframework.security.saml.provider.service.authentication.SamlResponseAuthenticationFilter;
import org.springframework.security.saml.provider.service.authentication.ServiceProviderLogoutHandler;
import org.springframework.security.saml.provider.service.authentication.SimpleAuthenticationManager;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public class SamlServiceProviderServerBeanConfiguration {

	private final SamlTransformer samlTransformer;
	private final SamlValidator samlValidator;
	private final SamlMetadataCache samlMetadataCache;
	private final SamlMessageStore<Assertion, HttpServletRequest> samlAssertionStore;
	private final SamlConfigurationRepository<HttpServletRequest> samlConfigurationRepository;

	protected SamlServiceProviderServerBeanConfiguration(SamlTransformer samlTransformer,
														 SamlValidator samlValidator,
														 SamlMetadataCache samlMetadataCache,
														 SamlMessageStore<Assertion, HttpServletRequest> samlAssertionStore,
														 SamlConfigurationRepository<HttpServletRequest> samlConfigurationRepository) {
		this.samlTransformer = samlTransformer;
		this.samlValidator = samlValidator;
		this.samlMetadataCache = samlMetadataCache;
		this.samlAssertionStore = samlAssertionStore;
		this.samlConfigurationRepository = samlConfigurationRepository;
	}

	public Filter samlConfigurationFilter() {
		return new ThreadLocalSamlConfigurationFilter(
			(ThreadLocalSamlConfigurationRepository) samlConfigurationRepository
		);
	}


	public Filter spMetadataFilter() {
		return new ServiceProviderMetadataFilter(getSamlProvisioning());
	}

	@Bean(name = "samlServiceProviderProvisioning")
	public SamlProviderProvisioning<ServiceProviderService> getSamlProvisioning() {
		return new HostBasedSamlServiceProviderProvisioning(
			samlConfigurationRepository,
			samlTransformer,
			samlValidator,
			samlMetadataCache
		);
	}

	public Filter spAuthenticationRequestFilter() {
		return new SamlAuthenticationRequestFilter(getSamlProvisioning());
	}

	public Filter spAuthenticationResponseFilter() {
		SamlResponseAuthenticationFilter authenticationFilter =
			new SamlResponseAuthenticationFilter(getSamlProvisioning());
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

}
