/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.validation.DefaultServiceProviderValidator;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml.serviceprovider.metadata.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.metadata.ServiceProviderMetadataResolver;
import org.springframework.security.saml.serviceprovider.web.DefaultServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.web.SamlAuthenticationFailureHandler;
import org.springframework.security.saml.serviceprovider.web.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.web.configuration.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.web.filters.AuthenticationRequestFilter;
import org.springframework.security.saml.serviceprovider.web.filters.SamlProcessingFilter;
import org.springframework.security.saml.serviceprovider.web.filters.SelectIdentityProviderUIFilter;
import org.springframework.security.saml.serviceprovider.web.filters.ServiceProviderLogoutFilter;
import org.springframework.security.saml.serviceprovider.web.filters.ServiceProviderMetadataFilter;
import org.springframework.security.saml.serviceprovider.web.filters.WebSsoAuthenticationFilter;
import org.springframework.security.saml.serviceprovider.web.html.HtmlWriter;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.security.saml.util.StringUtils;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.util.Optional.ofNullable;
import static org.springframework.util.Assert.notNull;

class SamlServiceProviderConfiguration {

	private HttpSecurity http;
	private SamlTransformer transformer;
	private ServiceProviderValidator validator;
	private SamlTemplateEngine engine;
	private ServiceProviderMetadataResolver metadataResolver;
	private ServiceProviderResolver providerResolver;
	private ServiceProviderConfigurationResolver configurationResolver;
	private HtmlWriter htmlWriter;
	private AuthenticationFailureHandler failureHandler;
	private AuthenticationManager authenticationManager;
	private AuthenticationEntryPoint authenticationEntryPoint;
	private String pathPrefix;

	SamlServiceProviderConfiguration() {
	}

	SamlServiceProviderConfiguration setProviderResolver(ServiceProviderResolver resolver) {
		notNull(resolver, "providerResolver must not be null");
		isNull(configurationResolver, "configurationResolver", "providerResolver");
		this.providerResolver = resolver;
		return this;
	}

	SamlServiceProviderConfiguration setAuthenticationManager(AuthenticationManager manager) {
		notNull(manager, "authenticationManager must not be null");
		this.authenticationManager = manager;
		return this;
	}

	SamlServiceProviderConfiguration setConfigurationResolver(ServiceProviderConfigurationResolver resolver) {
		notNull(resolver, "configurationResolver must not be null");
		isNull(providerResolver, "providerResolver", "configurationResolver");
		this.configurationResolver = resolver;
		return this;
	}

	SamlServiceProviderConfiguration authenticationFailureHandler(AuthenticationFailureHandler handler) {
		notNull(handler, "authenticationFailureHandler must not be null");
		this.failureHandler = handler;
		return this;
	}

	SamlServiceProviderConfiguration validate(HttpSecurity http) {
		this.http = http;
		getSamlTransformer();
		getSamlValidator();
		getSamlTemplateEngine();
		getSamlMetadataResolver();
		getServiceProviderResolver();
		getHtmlTemplateWriter();
		getAuthenticationFailureHandler();
		getAuthenticationManager();
		validateSamlConfiguration(http);
		this.pathPrefix = "/" + StringUtils.stripSlashes(getServiceProviderResolver().getConfiguredPathPrefix());
		return this;
	}

	String getPathPrefix() {
		return pathPrefix;
	}

	AuthenticationManager getAuthenticationManager() {
		authenticationManager = ofNullable(authenticationManager).orElseGet(() -> a -> a);
		return authenticationManager;
	}

	SamlProcessingFilter getSamlProcessingFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return new SamlProcessingFilter(
			transformer,
			providerResolver,
			validator,
			new AntPathRequestMatcher(pathPrefix + "/**")
		);
	}

	ServiceProviderLogoutFilter getLogoutFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			ServiceProviderLogoutFilter.class,
			() -> {
				SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
				logoutSuccessHandler.setDefaultTargetUrl(pathPrefix + "/select");
				return new ServiceProviderLogoutFilter(
					new AntPathRequestMatcher(pathPrefix + "/logout/**"),
					transformer,
					validator
				)
					.setLogoutSuccessHandler(logoutSuccessHandler);
			},
			null
		);
	}

	WebSsoAuthenticationFilter getWebSsoAuthenticationFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		WebSsoAuthenticationFilter filter = getSharedObject(
			http,
			WebSsoAuthenticationFilter.class,
			() -> new WebSsoAuthenticationFilter(
				new AntPathRequestMatcher(pathPrefix + "/SSO/**"),
				validator
			),
			null
		);
		filter.setAuthenticationManager(getAuthenticationManager());
		filter.setAuthenticationFailureHandler(getAuthenticationFailureHandler());
		return filter;
	}

	AuthenticationRequestFilter getIdentityProviderDiscoveryFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			AuthenticationRequestFilter.class,
			() -> new AuthenticationRequestFilter(
				new AntPathRequestMatcher(pathPrefix + "/discovery/**"),
				transformer,
				htmlWriter
			),
			null
		);
	}

	SelectIdentityProviderUIFilter getSelectIdentityProviderFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			SelectIdentityProviderUIFilter.class,
			() ->
				new SelectIdentityProviderUIFilter(
					pathPrefix,
					new AntPathRequestMatcher(pathPrefix + "/select/**"),
					htmlWriter
				)
					.setRedirectOnSingleProvider(false),
			null
		);
	}

	ServiceProviderMetadataFilter getMetadataFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			ServiceProviderMetadataFilter.class,
			() -> new ServiceProviderMetadataFilter(
				new AntPathRequestMatcher(pathPrefix + "/metadata/**"),
				transformer
			),
			null
		);
	}

	AuthenticationFailureHandler getAuthenticationFailureHandler() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		failureHandler = ofNullable(failureHandler)
			.orElseGet(() -> new SamlAuthenticationFailureHandler(htmlWriter));
		return failureHandler;
	}

	HtmlWriter getHtmlTemplateWriter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		htmlWriter = ofNullable(htmlWriter).orElseGet(() -> new HtmlWriter(engine));
		return htmlWriter;
	}

	ServiceProviderResolver getServiceProviderResolver() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		providerResolver = getSharedObject(
			http,
			ServiceProviderResolver.class,
			() -> null,
			providerResolver
		);
		return providerResolver;
	}

	ServiceProviderMetadataResolver getSamlMetadataResolver() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		metadataResolver = getSharedObject(
			http,
			ServiceProviderMetadataResolver.class,
			() -> new DefaultServiceProviderMetadataResolver(transformer),
			metadataResolver
		);
		return metadataResolver;
	}

	SamlTemplateEngine getSamlTemplateEngine() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		engine = getSharedObject(
			http,
			SamlTemplateEngine.class,
			() -> new VelocityTemplateEngine(true),
			engine
		);
		return engine;
	}

	ServiceProviderValidator getSamlValidator() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		validator = getSharedObject(
			http,
			ServiceProviderValidator.class,
			() -> new DefaultServiceProviderValidator(transformer),
			validator
		);
		return validator;
	}

	SamlTransformer getSamlTransformer() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		transformer = getSharedObject(
			http,
			SamlTransformer.class,
			this::createDefaultSamlTransformer,
			transformer
		);
		return transformer;
	}

	AuthenticationEntryPoint getAuthenticationEntryPoint() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		authenticationEntryPoint = getSharedObject(
			http,
			AuthenticationEntryPoint.class,
			() -> new LoginUrlAuthenticationEntryPoint(getPathPrefix() + "/select?redirect=true"),
			authenticationEntryPoint
		);

		return authenticationEntryPoint;
	}

	private boolean hasHttp() {
		return http != null;
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

			metadataResolver = getSamlMetadataResolver();
			providerResolver = new DefaultServiceProviderResolver(metadataResolver, configurationResolver);
			setSharedObject(http, ServiceProviderResolver.class, providerResolver);
		}
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

	private void isNull(Object configuredObject, String identifier, String alternate) {
		if (ofNullable(configuredObject).isPresent()) {
			throw new IllegalStateException(identifier + " should be null if you wish to configure a " + alternate);
		}
	}
}
