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

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.filters.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.serviceprovider.filters.SamlProcessAuthenticationResponseFilter;
import org.springframework.security.saml.serviceprovider.filters.SamlServiceProviderMetadataFilter;
import org.springframework.security.saml.serviceprovider.filters.SelectIdentityProviderUIFilter;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.spi.WebSamlTemplateProcessor;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.spi.ServiceProviderSamlValidator;
import org.springframework.security.saml.serviceprovider.spi.SingletonServiceProviderConfigurationResolver;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;
import static org.springframework.util.Assert.notNull;
import static org.springframework.util.StringUtils.hasText;

public class SamlServiceProviderConfigurer extends AbstractHttpConfigurer<SamlServiceProviderConfigurer, HttpSecurity> {

	public static SamlServiceProviderConfigurer saml2Login() {
		return new SamlServiceProviderConfigurer();
	}

	/*
	 * Fields with implementation defaults
	 */
	private String prefix = "/saml/sp";
	private SamlTransformer samlTransformer = null;
	private HostedServiceProviderConfiguration configuration;
	private SamlValidator samlValidator = null;
	private SamlTemplateEngine samlTemplateEngine = null;
	private AuthenticationManager authenticationManager = null;
	private ServiceProviderResolver resolver = null;
	private ServiceProviderConfigurationResolver configurationResolver;

	@Override
	public void init(HttpSecurity http) throws Exception {
		notNull(prefix, "SAML path prefix must not be null.");
		if (samlTransformer == null) {
			samlTransformer = createDefaultSamlTransformer();
		}

		if (samlValidator == null) {
			samlValidator = new ServiceProviderSamlValidator(samlTransformer);
		}
		if (samlTemplateEngine == null) {
			samlTemplateEngine = new VelocityTemplateEngine(true);
		}

		if (configurationResolver == null) {
			notNull(configuration, "SAML Service Provider Configuration must not be null.");
			if (!hasText(configuration.getPrefix())) {
				configuration = HostedServiceProviderConfiguration.Builder.builder(configuration)
					.withPrefix(prefix)
					.build();
			}
			configurationResolver = new SingletonServiceProviderConfigurationResolver(configuration);
		}

		if (resolver == null) {
			ServiceProviderMetadataResolver serviceProviderMetadataResolver =
				new DefaultServiceProviderMetadataResolver(samlTransformer);
			resolver = new DefaultServiceProviderResolver(serviceProviderMetadataResolver, configurationResolver);
		}

		String matchPrefix = "/" + stripSlashes(prefix);
		String samlPattern = matchPrefix + "/**";
		registerDefaultAuthenticationEntryPoint(http);
		http
			.csrf().ignoringAntMatchers(samlPattern)
			.and()
			.authorizeRequests()
			.antMatchers(samlPattern)
			.permitAll()
		;

	}

	@Override
	public void configure(HttpSecurity builder) throws Exception {
		WebSamlTemplateProcessor template = new WebSamlTemplateProcessor(samlTemplateEngine);
		String matchPrefix = "/" + stripSlashes(prefix);

		SamlServiceProviderMetadataFilter metadataFilter = new SamlServiceProviderMetadataFilter(
			new AntPathRequestMatcher(matchPrefix + "/metadata/**"),
			samlTransformer,
			resolver
		);

		SelectIdentityProviderUIFilter selectFilter = new SelectIdentityProviderUIFilter(
			prefix,
			new AntPathRequestMatcher(matchPrefix + "/select/**"),
			resolver,
			template
		)
			.setRedirectOnSingleProvider(false); //can cause loop until SSO logout

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


	@Autowired(required = false)
	public SamlServiceProviderConfigurer samlTransformer(SamlTransformer samlTransformer) {
		this.samlTransformer = samlTransformer;
		return this;
	}


	@Autowired(required = false)
	public SamlServiceProviderConfigurer samlValidator(SamlValidator samlValidator) {
		this.samlValidator = samlValidator;
		return this;
	}

	public SamlServiceProviderConfigurer prefix(String prefix) {
		this.prefix = prefix;
		return this;
	}

	@Autowired(required = false)
	public SamlServiceProviderConfigurer serviceProviderResolver(ServiceProviderResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	@Autowired(required = false)
	public SamlServiceProviderConfigurer samlTemplateEngine(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
		return this;
	}

	public SamlServiceProviderConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}


	@Autowired(required = false)
	public SamlServiceProviderConfigurer serviceProviderConfiguration(HostedServiceProviderConfiguration configuration) {
		this.configuration = configuration;
		return this;
	}

	@Autowired(required = false)
	public SamlServiceProviderConfigurer providerResolver(ServiceProviderResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	@Autowired(required = false)
	public SamlServiceProviderConfigurer configurationResolver(
		ServiceProviderConfigurationResolver configurationResolver
	) {
		this.configurationResolver = configurationResolver;
		return this;
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
			http.getConfigurer(ExceptionHandlingConfigurer.class);

		if (exceptionHandling == null) {
			return;
		}

		String entryPointUrl = "/" + stripSlashes(prefix)+"/select?redirect=true";
		LoginUrlAuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(entryPointUrl) {
			@Override
			public void commence(HttpServletRequest request,
								 HttpServletResponse response,
								 AuthenticationException authException) throws IOException, ServletException {
				super.commence(request, response, authException);
			}
		};
		exceptionHandling.authenticationEntryPoint(authenticationEntryPoint);
	}


	private SamlTransformer createDefaultSamlTransformer() {
		try {
			return getClassInstance("org.springframework.security.saml.spi.opensaml.OpenSamlTransformer");
		} catch (SamlException e) {
			try {
				return getClassInstance("org.springframework.security.saml.spi.keycloak.KeycloakSamlTransformer");
			} catch (SamlException e2) {
				throw e;
			}
		}
	}

	private SamlTransformer getClassInstance(String className) {
		try {
			Class<?> clazz = Class.forName(className, true, Thread.currentThread().getContextClassLoader());

			return (SamlTransformer) clazz.newInstance();
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
			throw new SamlException(
				"Unable to instantiate the default SAML transformer. " +
					"Have you included the transform-opensaml or transform-keycloak dependency in your project?",
				e
			);
		}
	}

}
