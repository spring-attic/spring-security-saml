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

package org.springframework.security.saml.serviceprovider;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.implementation.DefaultServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.implementation.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.serviceprovider.implementation.SamlProcessAuthenticationResponseFilter;
import org.springframework.security.saml.serviceprovider.implementation.SamlServiceProviderMetadataFilter;
import org.springframework.security.saml.serviceprovider.implementation.SamlTemplateProcessor;
import org.springframework.security.saml.serviceprovider.implementation.SelectIdentityProviderUIFilter;
import org.springframework.security.saml.serviceprovider.implementation.ServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.implementation.StaticServiceProviderConfigurationResolver;
import org.springframework.security.saml.spi.DefaultSamlValidator;
import org.springframework.security.saml.spi.SamlValidator;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;
import static org.springframework.util.Assert.notNull;

public class ServiceProviderDsl extends AbstractHttpConfigurer<ServiceProviderDsl, HttpSecurity> {

	public static ServiceProviderDsl serviceProvider() {
		return new ServiceProviderDsl();
	}

	/*
	 * User required fields
	 */
	private SamlTransformer samlTransformer = null;
	private HostedServiceProviderConfiguration configuration;

	/*
	 * Fields with implementation defaults
	 */
	private String prefix = "/saml/sp";
	private SamlValidator samlValidator = null;
	private SamlTemplateEngine samlTemplateEngine = null;
	private AuthenticationManager authenticationManager = null;
	private ServiceProviderResolver resolver = null;
	private SpConfigurationResolver configurationResolver;

	@Override
	public void init(HttpSecurity builder) throws Exception {
		notNull(prefix, "SAML path prefix must not be null.");
		notNull(samlTransformer, "SAML Core Transformer Implementation must not be null.");

		if (samlValidator == null) {
			samlValidator = new DefaultSamlValidator(samlTransformer);
		}
		if (samlTemplateEngine == null) {
			samlTemplateEngine = new VelocityTemplateEngine(true);
		}

		if (configurationResolver == null) {
			notNull(configuration, "SAML Service Provider Configuration must not be null.");
			configurationResolver = new StaticServiceProviderConfigurationResolver(configuration);
		}

		if (resolver == null) {
			ServiceProviderMetadataResolver serviceProviderMetadataResolver =
				new ServiceProviderMetadataResolver(samlTransformer);
			resolver = new DefaultServiceProviderResolver(serviceProviderMetadataResolver, configurationResolver);
		}

		String matchPrefix = "/" + stripSlashes(prefix);
		String samlPattern = matchPrefix + "/**";
		builder
			.csrf().ignoringAntMatchers(samlPattern)
			.and()
			.authorizeRequests()
			.antMatchers(samlPattern).permitAll()
		;

	}

	@Override
	public void configure(HttpSecurity builder) throws Exception {
		SamlTemplateProcessor template = new SamlTemplateProcessor(samlTemplateEngine);
		String matchPrefix = "/" + stripSlashes(prefix);

		SamlServiceProviderMetadataFilter metadataFilter = new SamlServiceProviderMetadataFilter(
			new AntPathRequestMatcher(matchPrefix + "/metadata/**"),
			samlTransformer,
			resolver
		);

		SelectIdentityProviderUIFilter selectFilter = new SelectIdentityProviderUIFilter(
			new AntPathRequestMatcher(matchPrefix + "/select/**"),
			resolver, template
		)
			.setRedirectOnSingleProvider(false); //avoid redirect loop upon logout

		SamlAuthenticationRequestFilter authnFilter = new SamlAuthenticationRequestFilter(
			new AntPathRequestMatcher(matchPrefix + "/discovery/**"),
			samlTransformer,
			resolver,
			template
		);

		SamlProcessAuthenticationResponseFilter authenticationFilter = new SamlProcessAuthenticationResponseFilter(
			new AntPathRequestMatcher(matchPrefix + "/SSO/**"),
			samlTransformer,
			samlValidator,
			resolver
		);
		if (authenticationManager != null) {
			authenticationFilter.setAuthenticationManager(authenticationManager);
		}

		builder.addFilterAfter(metadataFilter, BasicAuthenticationFilter.class);
		builder.addFilterAfter(selectFilter, metadataFilter.getClass());
		builder.addFilterAfter(authnFilter, selectFilter.getClass());
		builder.addFilterAfter(authenticationFilter, authnFilter.getClass());

	}

	public ServiceProviderDsl samlTransformer(SamlTransformer samlTransformer) {
		this.samlTransformer = samlTransformer;
		return this;
	}

	public ServiceProviderDsl samlValidator(SamlValidator samlValidator) {
		this.samlValidator = samlValidator;
		return this;
	}

	public ServiceProviderDsl prefix(String prefix) {
		this.prefix = prefix;
		return this;
	}

	public ServiceProviderDsl serviceProviderResolver(ServiceProviderResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	public ServiceProviderDsl samlTemplateEngine(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
		return this;
	}

	public ServiceProviderDsl authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public ServiceProviderDsl configuration(HostedServiceProviderConfiguration configuration) {
		this.configuration = configuration;
		return this;
	}

	public ServiceProviderDsl providerResolver(ServiceProviderResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	public ServiceProviderDsl configurationResolver(SpConfigurationResolver configurationResolver) {
		this.configurationResolver = configurationResolver;
		return this;
	}
}
