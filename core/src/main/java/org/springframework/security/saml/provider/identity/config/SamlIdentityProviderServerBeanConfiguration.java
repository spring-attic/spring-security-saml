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

package org.springframework.security.saml.provider.identity.config;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.SamlProviderLogoutFilter;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationFilter;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.identity.IdentityProviderLogoutHandler;
import org.springframework.security.saml.provider.identity.IdentityProviderMetadataFilter;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.IdpAuthenticationRequestFilter;
import org.springframework.security.saml.provider.identity.IdpInitiatedLoginFilter;
import org.springframework.security.saml.provider.identity.SelectServiceProviderFilter;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlIdentityProviderProvisioning;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public abstract class SamlIdentityProviderServerBeanConfiguration {

	private final SamlTransformer samlTransformer;
	private final SamlValidator samlValidator;
	private final SamlMetadataCache samlMetadataCache;
	private final SamlMessageStore<Assertion, HttpServletRequest> samlAssertionStore;
	private final SamlConfigurationRepository<HttpServletRequest> samlConfigurationRepository;

	protected SamlIdentityProviderServerBeanConfiguration(SamlTransformer samlTransformer,
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

	public Filter idpMetadataFilter() {
		return new IdentityProviderMetadataFilter(getSamlProvisioning());
	}


	@Bean(name = "samlIdentityProviderProvisioning")
	public SamlProviderProvisioning<IdentityProviderService> getSamlProvisioning() {
		return new HostBasedSamlIdentityProviderProvisioning(
			samlConfigurationRepository,
			samlTransformer,
			samlValidator,
			samlMetadataCache
		);
	}

	public Filter idpInitatedLoginFilter() {
		return new IdpInitiatedLoginFilter(getSamlProvisioning(), samlAssertionStore);
	}

	public Filter idpAuthnRequestFilter() {
		return new IdpAuthenticationRequestFilter(getSamlProvisioning(), samlAssertionStore);
	}

	public Filter idpLogoutFilter() {
		return new SamlProviderLogoutFilter<>(
			getSamlProvisioning(),
			new IdentityProviderLogoutHandler(getSamlProvisioning(), samlAssertionStore),
			new SimpleUrlLogoutSuccessHandler(),
			new SecurityContextLogoutHandler()
		);
	}

	public Filter idpSelectServiceProviderFilter() {
		return new SelectServiceProviderFilter(getSamlProvisioning());
	}

	@Bean(name = "idpSamlServerConfiguration")
	protected abstract SamlServerConfiguration getDefaultHostSamlServerConfiguration();
}
