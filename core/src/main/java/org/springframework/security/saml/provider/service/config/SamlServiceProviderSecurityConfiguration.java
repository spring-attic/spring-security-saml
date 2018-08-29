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

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.provider.SamlProviderLogoutFilter;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.AbstractProviderSecurityConfiguration;
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
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public class SamlServiceProviderSecurityConfiguration
	extends AbstractProviderSecurityConfiguration<ServiceProviderService> {

	public SamlServiceProviderSecurityConfiguration(SamlServerConfiguration hostConfiguration) {
		super(hostConfiguration);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		String prefix = getHostConfiguration().getServiceProvider().getPrefix();
		String matcher = "/" + stripSlashes(prefix) + "/**";
		String select = "/" + stripSlashes(prefix) + "/select";
		String metadata = "/" + stripSlashes(prefix) + "/metadata";
		http
			//.antMatcher(matcher)
			.addFilterAfter(samlConfigurationFilter(), BasicAuthenticationFilter.class)
			.addFilterAfter(spMetadataFilter(), samlConfigurationFilter().getClass())
			.addFilterAfter(spAuthenticationRequestFilter(), spMetadataFilter().getClass())
			.addFilterAfter(spAuthenticationResponseFilter(), spAuthenticationRequestFilter().getClass())
			.addFilterAfter(spSamlLogoutFilter(), spAuthenticationResponseFilter().getClass())
			.addFilterAfter(spSelectIdentityProviderFilter(), spSamlLogoutFilter().getClass())
			.csrf().disable()
			.authorizeRequests()
			.antMatchers(matcher).permitAll()
			.anyRequest().authenticated()
			.and()
			.formLogin().loginPage(select)
		;
	}

	@Bean
	public Filter spMetadataFilter() {
		return new ServiceProviderMetadataFilter(getSamlProvisioning());
	}

	@Bean
	public Filter spAuthenticationRequestFilter() {
		return new SamlAuthenticationRequestFilter(getSamlProvisioning());
	}

	@Bean
	public Filter spAuthenticationResponseFilter() {
		SamlResponseAuthenticationFilter authenticationFilter =
			new SamlResponseAuthenticationFilter(getSamlProvisioning());
		authenticationFilter.setAuthenticationManager(new SimpleAuthenticationManager());
		authenticationFilter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
		authenticationFilter.setAuthenticationFailureHandler(new GenericErrorAuthenticationFailureHandler());
		return authenticationFilter;
	}

	@Bean
	public Filter spSamlLogoutFilter() {
		return new SamlProviderLogoutFilter<>(
			getSamlProvisioning(),
			new ServiceProviderLogoutHandler(getSamlProvisioning()),
			new SimpleUrlLogoutSuccessHandler(),
			new SecurityContextLogoutHandler()
		);
	}

	@Bean
	public Filter spSelectIdentityProviderFilter() {
		return new SelectIdentityProviderFilter(getSamlProvisioning());
	}

	@Override
	@Bean(name = "samlServiceProviderProvisioning")
	public SamlProviderProvisioning<ServiceProviderService> getSamlProvisioning() {
		return new HostBasedSamlServiceProviderProvisioning(
			samlConfigurationRepository(),
			samlTransformer(),
			samlValidator(),
			samlMetadataCache(samlNetworkHandler())
		);
	}
}
