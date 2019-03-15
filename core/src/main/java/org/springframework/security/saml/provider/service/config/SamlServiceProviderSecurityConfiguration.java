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

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.provider.config.AbstractProviderSecurityConfiguration;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public abstract class SamlServiceProviderSecurityConfiguration
	extends AbstractProviderSecurityConfiguration<ServiceProviderService> {

	private static Log logger = LogFactory.getLog(SamlServiceProviderSecurityConfiguration.class);

	private SamlServiceProviderServerBeanConfiguration configuration;

	public SamlServiceProviderSecurityConfiguration(SamlServiceProviderServerBeanConfiguration configuration) {
		this("saml/sp/", configuration);
	}

	public SamlServiceProviderSecurityConfiguration(String prefix,
													SamlServiceProviderServerBeanConfiguration configuration) {
		super(stripSlashes(prefix+"/"));
		this.configuration = configuration;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		String prefix = getPrefix();

		String filterChainPattern = "/" + stripSlashes(prefix) + "/**";
		logger.info("Configuring SAML SP on pattern:"+filterChainPattern);
		http
			.antMatcher(filterChainPattern)
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/**").permitAll();


		http
			.addFilterAfter(
				getConfiguration().samlConfigurationFilter(),
				BasicAuthenticationFilter.class
			)
			.addFilterAfter(
				getConfiguration().spMetadataFilter(),
				getConfiguration().samlConfigurationFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().spAuthenticationRequestFilter(),
				getConfiguration().spMetadataFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().spAuthenticationResponseFilter(),
				getConfiguration().spAuthenticationRequestFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().spSamlLogoutFilter(),
				getConfiguration().spAuthenticationResponseFilter().getClass()
			)
			.addFilterAfter(
				getConfiguration().spSelectIdentityProviderFilter(),
				getConfiguration().spSamlLogoutFilter().getClass()
			)
		;
	}

	public SamlServiceProviderServerBeanConfiguration getConfiguration() {
		return configuration;
	}


}
