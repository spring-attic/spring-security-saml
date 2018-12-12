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

package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.Filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.serviceprovider.web.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.web.configuration.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.web.filters.SamlProcessingFilter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class SamlServiceProviderConfigurer extends AbstractHttpConfigurer<SamlServiceProviderConfigurer, HttpSecurity> {

	/*
	 * =========== Builders ============
	 */
	public static SamlServiceProviderConfigurer saml2Login() {
		return new SamlServiceProviderConfigurer();
	}

	public static SamlServiceProviderConfigurer saml2Login(ServiceProviderResolver resolver) {
		return saml2Login().providerResolver(resolver);
	}

	public static SamlServiceProviderConfigurer saml2Login(ServiceProviderConfigurationResolver resolver) {
		return saml2Login().configurationResolver(resolver);
	}

	/*
	 * =========== Builder configuration ============
	 */
	private SamlServiceProviderConfiguration configuration = new SamlServiceProviderConfiguration();

	/*
	 * =========== Setters ============
	 */
	/**
	 * Sets the configuration resolver for the SAML filter chain.
	 * This provides SAML Service Provider configuration based on an HTTP request
	 * and allows for tenant hosting based on {@link javax.servlet.http.HttpServletRequest}
	 * @param resolver - the configuration resolver to use
	 * @return this object to be used in a builder pattern
	 * @throws IllegalStateException if {@link #providerResolver(ServiceProviderResolver)} has been previously invoked
	 */
	public SamlServiceProviderConfigurer configurationResolver(
		ServiceProviderConfigurationResolver resolver
	) {
		configuration.setConfigurationResolver(resolver);
		return this;
	}

	/**
	 * Sets the service provider resolver for the SAML filter chain.
	 * This provides SAML Service Provider configuration and metadata based on an HTTP request
	 * and allows for tenant hosting based on {@link javax.servlet.http.HttpServletRequest}
	 * @param resolver - the SAML service provider resolver to use
	 * @return this object to be used in a builder pattern
	 * @throws IllegalStateException if {@link #configurationResolver(ServiceProviderConfigurationResolver)}
	 * has been previously invoked
	 */
	public SamlServiceProviderConfigurer providerResolver(ServiceProviderResolver resolver) {
		configuration.setProviderResolver(resolver);
		return this;
	}

	/**
	 * Overrides the default authentication manager
	 * @param manager the manager that will be invoked after an assertion has been successfully parsed
	 */
	public SamlServiceProviderConfigurer authenticationManager(AuthenticationManager manager) {
		configuration.setAuthenticationManager(manager);
		return this;
	}

	/**
	 * Overrides the default authentication failure handler to be invoked if we receive an invalid
	 * response or assertion
	 * @param handler the manager that will be invoked after an assertion has been successfully parsed
	 */
	public SamlServiceProviderConfigurer authenticationFailureHandler(AuthenticationFailureHandler handler) {
		configuration.authenticationFailureHandler(handler);
		return this;
	}

	/*
	 * =========== Implementation ============
	 */
	@Override
	public void init(HttpSecurity http) throws Exception {
		configuration.validate(http);
		String pathPrefix = configuration.getPathPrefix();
		String samlPattern = pathPrefix + "/**";
		registerDefaultAuthenticationEntryPoint(http, pathPrefix);

		http
			// @formatter:off
			.csrf()
				.ignoringAntMatchers(samlPattern)
				.and()
			.authorizeRequests()
				.mvcMatchers(samlPattern)
				.permitAll()
			// @formatter:on
		;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		Filter metadataFilter = configuration.getMetadataFilter();
		Filter selectIdentityProviderFilter = configuration.getSelectIdentityProviderFilter();
		Filter authenticationRequestFilter = configuration.getIdentityProviderDiscoveryFilter();
		AbstractAuthenticationProcessingFilter authenticationFilter = configuration.getWebSsoAuthenticationFilter();
		Filter logoutFilter = configuration.getLogoutFilter();
		SamlProcessingFilter processingFilter = configuration.getSamlProcessingFilter();

		http.addFilterAfter(processingFilter, BasicAuthenticationFilter.class);
		http.addFilterAfter(metadataFilter, processingFilter.getClass());
		http.addFilterAfter(selectIdentityProviderFilter, metadataFilter.getClass());
		http.addFilterAfter(authenticationRequestFilter, selectIdentityProviderFilter.getClass());
		http.addFilterAfter(authenticationFilter, authenticationRequestFilter.getClass());
		http.addFilterAfter(logoutFilter, authenticationFilter.getClass());
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http, String pathPrefix) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
			http.getConfigurer(ExceptionHandlingConfigurer.class);

		if (exceptionHandling == null) {
			return;
		}

		String entryPointUrl = pathPrefix + "/select?redirect=true";
		LoginUrlAuthenticationEntryPoint authenticationEntryPoint =
			new LoginUrlAuthenticationEntryPoint(entryPointUrl);
		exceptionHandling.authenticationEntryPoint(authenticationEntryPoint);
	}

}
