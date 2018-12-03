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
import java.util.function.Supplier;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.filters.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.serviceprovider.filters.SamlProcessAuthenticationResponseFilter;
import org.springframework.security.saml.serviceprovider.filters.SamlServiceProviderMetadataFilter;
import org.springframework.security.saml.serviceprovider.filters.SelectIdentityProviderUIFilter;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.spi.DefaultServiceProviderValidator;
import org.springframework.security.saml.serviceprovider.spi.SingletonServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.spi.WebSamlTemplateProcessor;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.util.Optional.ofNullable;
import static org.springframework.security.saml.util.StringUtils.stripSlashes;
import static org.springframework.util.Assert.notNull;

public class SamlServiceProviderConfigurer extends AbstractHttpConfigurer<SamlServiceProviderConfigurer, HttpSecurity> {

	public static SamlServiceProviderConfigurer saml2Login() {
		return new SamlServiceProviderConfigurer();
	}

	/*
	 * Fields with implementation defaults
	 */
	private SamlTransformer samlTransformer = null;
	private HostedServiceProviderConfiguration configuration;
	private ServiceProviderValidator samlValidator = null;
	private SamlTemplateEngine samlTemplateEngine = null;
	private AuthenticationManager authenticationManager = null;
	private ServiceProviderResolver serviceProviderResolver = null;
	private ServiceProviderMetadataResolver serviceProviderMetadataResolver = null;
	private ServiceProviderConfigurationResolver configurationResolver;

	@Override
	public void init(HttpSecurity http) throws Exception {

		samlTransformer = getSharedObject(
			http,
			SamlTransformer.class,
			() -> createDefaultSamlTransformer(),
			samlTransformer
		);

		samlValidator = getSharedObject(
			http,
			ServiceProviderValidator.class,
			() -> new DefaultServiceProviderValidator(samlTransformer),
			samlValidator
		);

		samlTemplateEngine = getSharedObject(
			http,
			SamlTemplateEngine.class,
			() -> new VelocityTemplateEngine(true),
			samlTemplateEngine
		);

		//do we have a configurationResolver?
		configurationResolver = getSharedObject(
			http,
			ServiceProviderConfigurationResolver.class,
			null,
			configurationResolver
		);

		if (configurationResolver == null) {
			configuration = getSharedObject(
				http,
				HostedServiceProviderConfiguration.class,
				null,
				configuration
			);
			notNull(
				configuration,
				HostedServiceProviderConfiguration.class.getName() + " or " +
					ServiceProviderConfigurationResolver.class.getName() + " must not be null"
			);
			notNull(
				configuration.getPathPrefix(),
				HostedServiceProviderConfiguration.class.getName() + ".getPathPrefix() must not return null."
			);
			configurationResolver = new SingletonServiceProviderConfigurationResolver(configuration);
			setSharedObject(http, ServiceProviderConfigurationResolver.class, configurationResolver);
		}
		else {
			notNull(
				configurationResolver.getPathPrefix(),
				ServiceProviderConfigurationResolver.class.getName() + ".getPathPrefix() must not return null."
			);
		}

		serviceProviderMetadataResolver = getSharedObject(
			http,
			ServiceProviderMetadataResolver.class,
			() -> new DefaultServiceProviderMetadataResolver(samlTransformer),
			serviceProviderMetadataResolver
		);

		serviceProviderResolver = getSharedObject(
			http,
			ServiceProviderResolver.class,
			() -> new DefaultServiceProviderResolver(serviceProviderMetadataResolver, configurationResolver),
			serviceProviderResolver
		);

		String pathPrefix = configurationResolver.getPathPrefix();
		String matchPrefix = "/" + stripSlashes(pathPrefix);
		String samlPattern = matchPrefix + "/**";
		registerDefaultAuthenticationEntryPoint(http, pathPrefix);
		// @formatter:off
		http
			.csrf()
				.ignoringAntMatchers(samlPattern)
				.and()
			.authorizeRequests()
				.mvcMatchers(samlPattern)
				.permitAll()
		;
		// @formatter:on

	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		String pathPrefix = configurationResolver.getPathPrefix();

		WebSamlTemplateProcessor template = new WebSamlTemplateProcessor(samlTemplateEngine);
		String matchPrefix = "/" + stripSlashes(pathPrefix);

		SamlServiceProviderMetadataFilter metadataFilter = new SamlServiceProviderMetadataFilter(
			new AntPathRequestMatcher(matchPrefix + "/metadata/**"),
			samlTransformer,
			serviceProviderResolver
		);

		SelectIdentityProviderUIFilter selectFilter = new SelectIdentityProviderUIFilter(
			pathPrefix,
			new AntPathRequestMatcher(matchPrefix + "/select/**"),
			serviceProviderResolver,
			template
		)
			.setRedirectOnSingleProvider(false); //can cause loop until SSO logout

		SamlAuthenticationRequestFilter authnFilter = new SamlAuthenticationRequestFilter(
			new AntPathRequestMatcher(matchPrefix + "/discovery/**"),
			samlTransformer,
			serviceProviderResolver,
			template
		);

		SamlProcessAuthenticationResponseFilter authenticationFilter = new SamlProcessAuthenticationResponseFilter(
			new AntPathRequestMatcher(matchPrefix + "/SSO/**"),
			samlTransformer,
			samlValidator,
			serviceProviderResolver
		);

		if (authenticationManager != null) {
			authenticationFilter.setAuthenticationManager(authenticationManager);
		}

		http.addFilterAfter(metadataFilter, BasicAuthenticationFilter.class);
		http.addFilterAfter(selectFilter, metadataFilter.getClass());
		http.addFilterAfter(authnFilter, selectFilter.getClass());
		http.addFilterAfter(authenticationFilter, authnFilter.getClass());

	}

	public SamlServiceProviderConfigurer samlTransformer(SamlTransformer samlTransformer) {
		this.samlTransformer = samlTransformer;
		return this;
	}

	public SamlServiceProviderConfigurer samlValidator(ServiceProviderValidator samlValidator) {
		this.samlValidator = samlValidator;
		return this;
	}

	public SamlServiceProviderConfigurer serviceProviderResolver(ServiceProviderResolver resolver) {
		this.serviceProviderResolver = resolver;
		return this;
	}

	public SamlServiceProviderConfigurer samlTemplateEngine(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
		return this;
	}

	public SamlServiceProviderConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public SamlServiceProviderConfigurer serviceProviderConfiguration(HostedServiceProviderConfiguration configuration) {
		this.configuration = configuration;
		return this;
	}

	public SamlServiceProviderConfigurer providerResolver(ServiceProviderResolver resolver) {
		this.serviceProviderResolver = resolver;
		return this;
	}

	public SamlServiceProviderConfigurer configurationResolver(
		ServiceProviderConfigurationResolver configurationResolver
	) {
		this.configurationResolver = configurationResolver;
		return this;
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http, String pathPrefix) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
			http.getConfigurer(ExceptionHandlingConfigurer.class);

		if (exceptionHandling == null) {
			return;
		}

		String entryPointUrl = "/" + stripSlashes(pathPrefix) + "/select?redirect=true";
		LoginUrlAuthenticationEntryPoint authenticationEntryPoint =
			new LoginUrlAuthenticationEntryPoint(entryPointUrl) {
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

	private <C> C getSharedObject(HttpSecurity http, Class<C> clazz) {
		return http.getSharedObject(clazz);
	}

	private <C> void setSharedObject(HttpSecurity http, Class<C> clazz, C object) {
		if (http.getSharedObject(clazz) == null) {
			http.setSharedObject(clazz, object);
		}
	}

	private <C> C getSharedObject(HttpSecurity http,
								  Class<C> clazz,
								  Supplier<C> creator,
								  C existingInstance) {
		C result = ofNullable(existingInstance).orElseGet(() -> getSharedObject(http, clazz));
		if (result == null) {
			ApplicationContext context = getSharedObject(http, ApplicationContext.class);
			try {
				result = context.getBean(clazz);
			} catch (NoSuchBeanDefinitionException e) {
				if (creator != null) {
					result = creator.get();
				}
				else {
					return null;
				}
			}
		}
		setSharedObject(http, clazz, result);
		return result;
	}

}
