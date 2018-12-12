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

import java.util.function.Supplier;
import javax.servlet.Filter;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.serviceprovider.metadata.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.metadata.ServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.validation.DefaultServiceProviderValidator;
import org.springframework.security.saml.serviceprovider.validation.ServiceProviderValidator;
import org.springframework.security.saml.serviceprovider.web.DefaultServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.web.SamlAuthenticationFailureHandler;
import org.springframework.security.saml.serviceprovider.web.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.web.configuration.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.web.filters.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.serviceprovider.web.filters.SamlProcessingFilter;
import org.springframework.security.saml.serviceprovider.web.filters.SamlServiceProviderMetadataFilter;
import org.springframework.security.saml.serviceprovider.web.filters.SamlWebSsoAuthenticationFilter;
import org.springframework.security.saml.serviceprovider.web.filters.SelectIdentityProviderUIFilter;
import org.springframework.security.saml.serviceprovider.web.filters.ServiceProviderLogoutFilter;
import org.springframework.security.saml.serviceprovider.web.html.HtmlWriter;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.security.saml.util.StringUtils;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.util.Optional.ofNullable;
import static org.springframework.util.Assert.notNull;

public class SamlServiceProviderConfigurer extends AbstractHttpConfigurer<SamlServiceProviderConfigurer, HttpSecurity> {

	public static SamlServiceProviderConfigurer saml2Login() {
		return new SamlServiceProviderConfigurer();
	}

	/*
	 * Fields with implementation defaults
	 */
	private ServiceProviderResolver providerResolver = null;
	private SamlTransformer samlTransformer = null;
	private ServiceProviderValidator samlValidator = null;
	private SamlTemplateEngine samlTemplateEngine = null;
	private AuthenticationManager authenticationManager = null;
	private ServiceProviderMetadataResolver metadataResolver = null;
	private ServiceProviderConfigurationResolver configurationResolver;
	private HtmlWriter htmlTemplateProcessor;
	private AuthenticationFailureHandler failureHandler;

	/*
	 * Filters for handling requests
	 */
	private Filter metadataFilter;
	private Filter selectIdentityProviderFilter;
	private Filter authenticationRequestFilter;
	private AbstractAuthenticationProcessingFilter authenticationFilter;
	private Filter logoutFilter;

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
		notNull(resolver, "configurationResolver must not be null");
		assertNull(providerResolver, "providerResolver", "configurationResolver");
		this.configurationResolver = resolver;
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
		notNull(resolver, "providerResolver must not be null");
		assertNull(configurationResolver, "configurationResolver", "providerResolver");
		this.providerResolver = resolver;
		return this;
	}

	/*
	 * Configuration
	 */
	@Override
	public void init(HttpSecurity http) throws Exception {
		samlTransformer = getSamlTransformer(http);
		samlValidator = getSamlValidator(http);
		samlTemplateEngine = getSamlTemplateEngine(http);
		metadataResolver = getSamlMetadataResolver(http);
		providerResolver = getServiceProviderResolver(http);
		htmlTemplateProcessor = getHtmlTemplateWriter();
		failureHandler = getAuthenticationFailureHandler();

		validateSamlConfiguration(http);
		String samlPattern = getPathPrefix(providerResolver.getConfiguredPathPrefix()) + "/**";
		registerDefaultAuthenticationEntryPoint(http, getPathPrefix(providerResolver.getConfiguredPathPrefix()));

		if (!isPreviouslyInitialized(http)) {
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
			setInitializationCompleted(http);
		}
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		if (!isPreviouslyConfigured(http)) {
			String pathPrefix = getPathPrefix(providerResolver.getConfiguredPathPrefix());
			metadataFilter = getMetadataFilter(http, pathPrefix);
			selectIdentityProviderFilter = getSelectIdentityProviderFilter(http, pathPrefix);
			authenticationRequestFilter = getIdentityProviderDiscoveryFilter(http, pathPrefix);
			authenticationFilter = getWebSsoAuthenticationFilter(http, pathPrefix);
			authenticationFilter.setAuthenticationManager(ofNullable(authenticationManager).orElseGet(() -> a -> a));
			authenticationFilter.setAuthenticationFailureHandler(failureHandler);
			logoutFilter = getLogoutFilter(http, pathPrefix);
			SamlProcessingFilter processingFilter = getSamlProcessingFilter(pathPrefix);

			http.addFilterAfter(processingFilter, BasicAuthenticationFilter.class);
			http.addFilterAfter(metadataFilter, processingFilter.getClass());
			http.addFilterAfter(selectIdentityProviderFilter, metadataFilter.getClass());
			http.addFilterAfter(authenticationRequestFilter, selectIdentityProviderFilter.getClass());
			http.addFilterAfter(authenticationFilter, authenticationRequestFilter.getClass());
			http.addFilterAfter(logoutFilter, authenticationFilter.getClass());
			setConfigurationCompleted(http);
		}
	}

	private void validateSamlConfiguration(HttpSecurity http) {
		if (ofNullable(providerResolver).isPresent()) {
			notNull(
				providerResolver.getConfiguredPathPrefix(),
				ServiceProviderResolver.class.getName() + ".getConfiguredPathPrefix() must not return null"
			);
		}
		else {
			//do we have a configurationResolver?
			configurationResolver = getSharedObject(
				http,
				ServiceProviderConfigurationResolver.class,
				null,
				configurationResolver
			);

			notNull(
				configurationResolver,
				ServiceProviderConfigurationResolver.class.getName() + " must not be null"
			);

			notNull(
				configurationResolver.getConfiguredPathPrefix(),
				ServiceProviderConfigurationResolver.class.getName() + ".getConfiguredPathPrefix() must not return null"
			);

			providerResolver = new DefaultServiceProviderResolver(metadataResolver, configurationResolver);
			setSharedObject(http, ServiceProviderResolver.class, providerResolver);
		}
	}

	private SamlProcessingFilter getSamlProcessingFilter(String pathPrefix) {
		return new SamlProcessingFilter(
			samlTransformer,
			providerResolver,
			samlValidator,
			new AntPathRequestMatcher(pathPrefix + "/**")
		);
	}

	private ServiceProviderLogoutFilter getLogoutFilter(HttpSecurity http, String pathPrefix) {
		return getSharedObject(
			http,
			ServiceProviderLogoutFilter.class,
			() -> {
				SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
				logoutSuccessHandler.setDefaultTargetUrl(pathPrefix + "/select");
				return new ServiceProviderLogoutFilter(
					new AntPathRequestMatcher(pathPrefix + "/logout/**"),
					samlTransformer,
					samlValidator
				)
					.setLogoutSuccessHandler(logoutSuccessHandler);
			},
			logoutFilter
		);
	}

	private SamlWebSsoAuthenticationFilter getWebSsoAuthenticationFilter(HttpSecurity http, String pathPrefix) {
		return getSharedObject(
			http,
			SamlWebSsoAuthenticationFilter.class,
			() -> new SamlWebSsoAuthenticationFilter(
				new AntPathRequestMatcher(pathPrefix + "/SSO/**"),
				samlValidator
			),
			authenticationFilter
		);
	}

	private SamlAuthenticationRequestFilter getIdentityProviderDiscoveryFilter(HttpSecurity http, String pathPrefix) {
		return getSharedObject(
			http,
			SamlAuthenticationRequestFilter.class,
			() -> new SamlAuthenticationRequestFilter(
				new AntPathRequestMatcher(pathPrefix + "/discovery/**"),
				samlTransformer,
				htmlTemplateProcessor
			),
			authenticationRequestFilter
		);
	}

	private SelectIdentityProviderUIFilter getSelectIdentityProviderFilter(HttpSecurity http, String pathPrefix) {
		return getSharedObject(
			http,
			SelectIdentityProviderUIFilter.class,
			() ->
				new SelectIdentityProviderUIFilter(
					pathPrefix,
					new AntPathRequestMatcher(pathPrefix + "/select/**"),
					htmlTemplateProcessor
				)
					.setRedirectOnSingleProvider(false),
			selectIdentityProviderFilter
		);
	}

	private SamlServiceProviderMetadataFilter getMetadataFilter(HttpSecurity http, String pathPrefix) {
		return getSharedObject(
			http,
			SamlServiceProviderMetadataFilter.class,
			() -> new SamlServiceProviderMetadataFilter(
				new AntPathRequestMatcher(pathPrefix + "/metadata/**"),
				samlTransformer
			),
			metadataFilter
		);
	}

	private AuthenticationFailureHandler getAuthenticationFailureHandler() {
		return new SamlAuthenticationFailureHandler(htmlTemplateProcessor);
	}

	private HtmlWriter getHtmlTemplateWriter() {
		return new HtmlWriter(samlTemplateEngine);
	}

	private ServiceProviderResolver getServiceProviderResolver(HttpSecurity http) {
		return getSharedObject(
			http,
			ServiceProviderResolver.class,
			() -> null,
			providerResolver
		);
	}

	private ServiceProviderMetadataResolver getSamlMetadataResolver(HttpSecurity http) {
		return getSharedObject(
			http,
			ServiceProviderMetadataResolver.class,
			() -> new DefaultServiceProviderMetadataResolver(samlTransformer),
			metadataResolver
		);
	}

	private SamlTemplateEngine getSamlTemplateEngine(HttpSecurity http) {
		return getSharedObject(
			http,
			SamlTemplateEngine.class,
			() -> new VelocityTemplateEngine(true),
			samlTemplateEngine
		);
	}

	private ServiceProviderValidator getSamlValidator(HttpSecurity http) {
		return getSharedObject(
			http,
			ServiceProviderValidator.class,
			() -> new DefaultServiceProviderValidator(samlTransformer),
			samlValidator
		);
	}

	private SamlTransformer getSamlTransformer(HttpSecurity http) {
		return getSharedObject(
			http,
			SamlTransformer.class,
			this::createDefaultSamlTransformer,
			samlTransformer
		);
	}

	private String getPathPrefix(String pathPrefix) {
		return "/" + StringUtils.stripSlashes(pathPrefix);
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
								  Supplier<? extends C> creator,
								  Object existingInstance) {
		C result = ofNullable((C) existingInstance).orElseGet(() -> getSharedObject(http, clazz));
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

	private void assertNull(Object configuredObject, String identifier, String alternate) {
		if (ofNullable(configuredObject).isPresent()) {
			throw new IllegalStateException(identifier +" should be null if you wish to configure a "+ alternate);
		}
	}

	private boolean isPreviouslyInitialized(HttpSecurity http) {
		return http.getSharedObject(ServiceProviderInitialized.class) != null;
	}

	private void setInitializationCompleted(HttpSecurity http) {
		http.setSharedObject(ServiceProviderInitialized.class, new ServiceProviderInitialized());
	}

	private boolean isPreviouslyConfigured(HttpSecurity http) {
		return http.getSharedObject(ServiceProviderConfigured.class) != null;
	}

	private void setConfigurationCompleted(HttpSecurity http) {
		http.setSharedObject(ServiceProviderConfigured.class, new ServiceProviderConfigured());
	}

	private static class ServiceProviderInitialized{}
	private static class ServiceProviderConfigured{}

}
