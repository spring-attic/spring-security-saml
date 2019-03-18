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

package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.Filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.serviceprovider.ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.ServiceProviderConfigurationResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class SamlServiceProviderConfigurer extends AbstractHttpConfigurer<SamlServiceProviderConfigurer, HttpSecurity> {

	/*
	 * =========== Builders ============
	 */

	/**
	 * Creates a SAML service provider and installs all the service endpoints
	 * in the filter chain this configurer is applied to
	 * @return configuration spec for a SAML service provider to be applied to a filter chain
	 */
	public static SamlServiceProviderConfigurer saml2Login() {
		return new SamlServiceProviderConfigurer();
	}

	/**
	 * Creates a SAML service provider using minimum required configuration and installs all the service endpoints
	 * in the filter chain this configurer is applied to
	 * This is a mutually exclusive option to {@link #saml2Login(ServiceProviderConfigurationResolver)}
	 * @param resolver pre configures the {@link ServiceProviderResolver}. This is the minimum the
	 *                 configuration needed for a service provider to run in a servlet container
	 * @return configuration spec for a SAML service provider to be applied to a filter chain
	 */
	public static SamlServiceProviderConfigurer saml2Login(ServiceProviderResolver resolver) {
		return saml2Login().providerResolver(resolver);
	}

	/**
	 * Creates a SAML service provider using minimum required configuration and installs all the service endpoints
	 * in the filter chain this configurer is applied to
	 * This is a mutually exclusive option to {@link #saml2Login(ServiceProviderResolver)}
	 * @param resolver pre configures the {@link ServiceProviderConfigurationResolver}. This is the minimum the
	 *                 configuration needed for a service provider to run in a servlet container
	 * @return configuration spec for a SAML service provider to be applied to a filter chain
	 */
	public static SamlServiceProviderConfigurer saml2Login(ServiceProviderConfigurationResolver resolver) {
		return saml2Login().configurationResolver(resolver);
	}

	/**
	 * Installs an {@link AuthenticationEntryPoint} in the filter chain this configurer is applied to
	 * This is used for filterchains that should redirect for SAML login but do not service up the SAML
	 * endpoints under the configured SAML prefix path.
	 * You only use this option if you have more than one filter chain in your application.
	 * @return configuration spec for a SAML service provider {@link AuthenticationEntryPoint}
	 *         to be applied to a filter chain
	 */
	public static SamlServiceProviderConfigurer saml2AuthenticationEntryPoint() {
		final SamlServiceProviderConfigurer configurer = saml2Login();
		configurer.installEndpoints = false;
		return configurer;
	}

	/*
	 * =========== Builder configuration ============
	 */
	private SamlServiceProviderConfiguration configuration = new SamlServiceProviderConfiguration();
	private boolean installEndpoints = true;

	/*
	 * =========== Setters ============
	 */

	/**
	 * Sets the configuration resolver for the SAML filter chain.
	 * This provides SAML Service Provider configuration based on an HTTP request
	 * and allows for tenant hosting based on {@link javax.servlet.http.HttpServletRequest}
	 *
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
	 *
	 * @param resolver - the SAML service provider resolver to use
	 * @return this object to be used in a builder pattern
	 * @throws IllegalStateException if {@link #configurationResolver(ServiceProviderConfigurationResolver)}
	 *                               has been previously invoked
	 */
	public SamlServiceProviderConfigurer providerResolver(ServiceProviderResolver resolver) {
		configuration.setProviderResolver(resolver);
		return this;
	}

	/**
	 * Overrides the default authentication manager
	 *
	 * @param manager the manager that will be invoked after an assertion has been successfully parsed
	 */
	public SamlServiceProviderConfigurer authenticationManager(AuthenticationManager manager) {
		configuration.setAuthenticationManager(manager);
		return this;
	}

	/**
	 * Overrides the default authentication failure handler to be invoked if we receive an invalid
	 * response or assertion
	 *
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
		registerDefaultAuthenticationEntryPoint(http, configuration.getAuthenticationEntryPoint());

		if (installEndpoints) {
			String pathPrefix = configuration.getPathPrefix();
			String samlPattern = pathPrefix + "/**";
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
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		if (installEndpoints) {
			configureFilters(
				http,
				BasicAuthenticationFilter.class,
				configuration.getMetadataFilter(),
				configuration.getStaticLoginPageFilter(),
				configuration.getSelectIdentityProviderFilter(),
				configuration.getAuthenticationRequestFilter(),
				configuration.getWebSsoAuthenticationFilter(),
				configuration.getLogoutFilter()
			);
		}
	}

	protected void configureFilters(HttpSecurity http,
									Class<? extends Filter> afterFilter,
									Filter... filters) {
		for (Filter f : filters) {
			http.addFilterAfter(f, afterFilter);
			afterFilter = f.getClass();
		}
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http, AuthenticationEntryPoint entryPoint) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
			http.getConfigurer(ExceptionHandlingConfigurer.class);

		if (exceptionHandling == null) {
			return;
		}

		exceptionHandling.authenticationEntryPoint(entryPoint);
	}

}
