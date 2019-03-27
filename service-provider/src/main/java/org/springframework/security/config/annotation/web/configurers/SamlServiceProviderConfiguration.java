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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.provider.validation.DefaultSaml2ServiceProviderValidator;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.ServiceProviderConfigurationResolver;
import org.springframework.security.saml2.serviceprovider.ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.metadata.DefaultServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.metadata.ServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.web.WebServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.web.filters.Saml2WebAuthenticationRequestResolver;
import org.springframework.security.saml2.serviceprovider.web.filters.Saml2AuthenticationRequestFilter;
import org.springframework.security.saml2.serviceprovider.web.filters.SamlAuthenticationFailureHandler;
import org.springframework.security.saml2.serviceprovider.web.filters.Saml2LoginPageGeneratingFilter;
import org.springframework.security.saml2.serviceprovider.web.filters.ServiceProviderLogoutFilter;
import org.springframework.security.saml2.serviceprovider.web.filters.ServiceProviderMetadataFilter;
import org.springframework.security.saml2.serviceprovider.web.filters.WebSsoAuthenticationFilter;
import org.springframework.security.saml2.util.Saml2StringUtils;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Optional.ofNullable;
import static org.springframework.security.saml2.util.Saml2StringUtils.stripSlashes;
import static org.springframework.util.Assert.notNull;

class SamlServiceProviderConfiguration {

	private static Log logger = LogFactory.getLog(SamlServiceProviderConfiguration.class);

	private HttpSecurity http;
	private Saml2Transformer transformer;
	private Saml2ServiceProviderValidator validator;
	private ServiceProviderMetadataResolver metadataResolver;
	private ServiceProviderResolver providerResolver;
	private ServiceProviderConfigurationResolver configurationResolver;
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
		getSamlMetadataResolver();
		getServiceProviderResolver();
		getAuthenticationFailureHandler();
		getAuthenticationManager();
		validateSamlConfiguration(http);
		this.pathPrefix = "/" + Saml2StringUtils.stripSlashes(getServiceProviderResolver().getConfiguredPathPrefix());
		return this;
	}

	String getPathPrefix() {
		return pathPrefix;
	}

	AuthenticationManager getAuthenticationManager() {
		authenticationManager = ofNullable(authenticationManager).orElseGet(() -> a -> a);
		return authenticationManager;
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
					transformer,
					providerResolver,
					validator,
					new AntPathRequestMatcher(pathPrefix + "/logout/**")
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
				transformer,
				providerResolver,
				validator,
				new AntPathRequestMatcher(pathPrefix + "/SSO/**")
			),
			null
		);
		filter.setAuthenticationManager(getAuthenticationManager());
		filter.setAuthenticationFailureHandler(getAuthenticationFailureHandler());
		return filter;
	}

	Saml2AuthenticationRequestFilter getAuthenticationRequestFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2AuthenticationRequestFilter.class,
			() -> new Saml2AuthenticationRequestFilter(
				new Saml2WebAuthenticationRequestResolver(
					transformer,
					providerResolver,
					validator
				),
				new AntPathRequestMatcher(pathPrefix + "/authenticate/**")
			),
			null
		);
	}

	Saml2LoginPageGeneratingFilter getStaticLoginPageFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2LoginPageGeneratingFilter.class,
			() ->
				new Saml2LoginPageGeneratingFilter(
					new AntPathRequestMatcher(pathPrefix + "/login/**"),
					getStaticLoginUrls()
				),
			null
		);
	}

	ServiceProviderMetadataFilter getMetadataFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			ServiceProviderMetadataFilter.class,
			() -> new ServiceProviderMetadataFilter(
				transformer,
				providerResolver,
				validator,
				new AntPathRequestMatcher(pathPrefix + "/metadata/**")
			),
			null
		);
	}

	AuthenticationFailureHandler getAuthenticationFailureHandler() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		failureHandler = ofNullable(failureHandler)
			.orElseGet(() -> new SamlAuthenticationFailureHandler());
		return failureHandler;
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

	Saml2ServiceProviderValidator getSamlValidator() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		validator = getSharedObject(
			http,
			Saml2ServiceProviderValidator.class,
			() -> new DefaultSaml2ServiceProviderValidator(transformer),
			validator
		);
		return validator;
	}

	Saml2Transformer getSamlTransformer() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		transformer = getSharedObject(
			http,
			Saml2Transformer.class,
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
			() -> new LoginUrlAuthenticationEntryPoint(getPathPrefix() + "/login"),
			authenticationEntryPoint
		);

		return authenticationEntryPoint;
	}

	private Map<String, String> getStaticLoginUrls() {
		final ServiceProviderConfigurationResolver configResolver = getSharedObject(
			http,
			ServiceProviderConfigurationResolver.class,
			() -> null,
			configurationResolver
		);
		HostedSaml2ServiceProviderConfiguration configuration = configResolver.getConfiguration(null);
		Map<String, String> providerUrls = new HashMap<>();
		configuration.getProviders().stream().forEach(
			p -> {
				String linkText = p.getLinktext();
				String url = "/" +
					stripSlashes(pathPrefix) +
					"/authenticate/" +
					UriUtils.encode(p.getAlias(), UTF_8.toString());
				providerUrls.put(linkText, url);

			}
		);
		return providerUrls;
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
			providerResolver = new WebServiceProviderResolver(metadataResolver, configurationResolver);
			setSharedObject(http, ServiceProviderResolver.class, providerResolver);
		}
	}


	private Saml2Transformer createDefaultSamlTransformer() {
		try {
			return getClassInstance("org.springframework.security.saml2.spi.opensaml.OpenSamlTransformer");
		} catch (Saml2Exception e) {
			try {
				return getClassInstance("org.springframework.security.saml2.spi.keycloak.KeycloakSamlTransformer");
			} catch (Saml2Exception e2) {
				throw e;
			}
		}
	}

	private Saml2Transformer getClassInstance(String className) {
		try {
			Class<?> clazz = Class.forName(className, true, Thread.currentThread().getContextClassLoader());
			return (Saml2Transformer) clazz.newInstance();
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
			throw new Saml2Exception(
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
