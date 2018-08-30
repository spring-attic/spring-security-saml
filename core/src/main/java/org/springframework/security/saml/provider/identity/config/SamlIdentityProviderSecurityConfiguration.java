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

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.provider.config.AbstractProviderSecurityConfiguration;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public abstract class SamlIdentityProviderSecurityConfiguration
	extends AbstractProviderSecurityConfiguration<IdentityProviderService> {

	private final SamlIdentityProviderServerBeanConfiguration configuration;

	public SamlIdentityProviderSecurityConfiguration(SamlIdentityProviderServerBeanConfiguration configuration) {
		this("saml/idp/", configuration);
	}

	public SamlIdentityProviderSecurityConfiguration(String prefix,
													 SamlIdentityProviderServerBeanConfiguration configuration) {
		super(prefix);
		this.configuration = configuration;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		String prefix = getPrefix();
		String matcher = "/" + stripSlashes(prefix) + "/**";
		String metadata = "/" + stripSlashes(prefix) + "/metadata";
		http
			//.antMatcher(matcher)
			.addFilterAfter(
				getConfiguration().samlConfigurationFilter(),
				BasicAuthenticationFilter.class
			)
			.addFilterAfter(
				getConfiguration().idpMetadataFilter(),
				getConfiguration().samlConfigurationFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().idpInitatedLoginFilter(),
				getConfiguration().idpMetadataFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().idpAuthnRequestFilter(),
				getConfiguration().idpInitatedLoginFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().idpLogoutFilter(),
				getConfiguration().idpAuthnRequestFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().idpSelectServiceProviderFilter(),
				getConfiguration().idpLogoutFilter().getClass()
			)
			.csrf().disable()
			.authorizeRequests()
			.antMatchers(metadata).permitAll()
			.anyRequest().authenticated()
		;
	}

	public SamlIdentityProviderServerBeanConfiguration getConfiguration() {
		return configuration;
	}
}
