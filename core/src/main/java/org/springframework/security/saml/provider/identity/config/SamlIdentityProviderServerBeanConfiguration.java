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

package org.springframework.security.saml.provider.identity.config;

import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.provider.SamlProviderLogoutFilter;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.AbstractSamlServerBeanConfiguration;
import org.springframework.security.saml.provider.identity.AssertionEnhancer;
import org.springframework.security.saml.provider.identity.IdentityProviderLogoutHandler;
import org.springframework.security.saml.provider.identity.IdentityProviderMetadataFilter;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.IdpAuthenticationRequestFilter;
import org.springframework.security.saml.provider.identity.IdpInitiatedLoginFilter;
import org.springframework.security.saml.provider.identity.ResponseEnhancer;
import org.springframework.security.saml.provider.identity.SelectServiceProviderFilter;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlIdentityProviderProvisioning;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public abstract class SamlIdentityProviderServerBeanConfiguration
	extends AbstractSamlServerBeanConfiguration<IdentityProviderService> {

	public Filter idpMetadataFilter() {
		return new IdentityProviderMetadataFilter(getSamlProvisioning());
	}

	@Bean(name = "samlAssertionEnhancer")
	public AssertionEnhancer samlAssertionEnhancer() {
		return assertion -> assertion;
	}

	@Bean(name = "samlResponseEnhancer")
	public ResponseEnhancer samlResponseEnhancer() {
		return response -> response;
	}

	@Override
	@Bean(name = "samlIdentityProviderProvisioning")
	public SamlProviderProvisioning<IdentityProviderService> getSamlProvisioning() {
		return new HostBasedSamlIdentityProviderProvisioning(
			samlConfigurationRepository(),
			samlTransformer(),
			samlValidator(),
			samlMetadataCache(),
			samlAssertionEnhancer(),
			samlResponseEnhancer()
		);
	}

	public Filter idpInitatedLoginFilter() {
		return new IdpInitiatedLoginFilter(getSamlProvisioning(), samlAssertionStore());
	}

	public Filter idpAuthnRequestFilter() {
		return new IdpAuthenticationRequestFilter(getSamlProvisioning(), samlAssertionStore());
	}

	public Filter idpLogoutFilter() {
		return new SamlProviderLogoutFilter<>(
			getSamlProvisioning(),
			new IdentityProviderLogoutHandler(getSamlProvisioning(), samlAssertionStore()),
			new SimpleUrlLogoutSuccessHandler(),
			new SecurityContextLogoutHandler()
		);
	}

	public Filter idpSelectServiceProviderFilter() {
		return new SelectServiceProviderFilter(getSamlProvisioning());
	}

	@Override
	@Bean(name = "idpSamlServerConfiguration")
	protected abstract SamlServerConfiguration getDefaultHostSamlServerConfiguration();
}
