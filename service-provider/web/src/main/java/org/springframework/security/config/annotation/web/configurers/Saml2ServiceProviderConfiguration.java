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
import javax.servlet.Filter;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.provider.validation.DefaultSaml2ServiceProviderValidator;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderConfigurationResolver;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.metadata.Saml2ServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.web.DefaultSaml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.web.authentication.DefaultSaml2AuthenticationRequestResolver;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2AuthenticationFailureHandler;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2AuthenticationRequestFilter;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2HttpMessageResponder;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2LoginPageGeneratingFilter;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2ServiceProviderLogoutFilter;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2ServiceProviderMetadataFilter;
import org.springframework.security.saml2.serviceprovider.web.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.serviceprovider.web.metadata.DefaultSaml2ServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.web.util.Saml2ServiceProviderMethods;
import org.springframework.security.saml2.util.Saml2StringUtils;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
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

class Saml2ServiceProviderConfiguration implements BeanClassLoaderAware {

	public static final String SAML2_TRANSFORMER_OPEN_SAML =
		"org.springframework.security.saml2.spi.opensaml.OpenSaml2Transformer";
	public static final String SAML2_TRANSFORMER_KEYCLOAK =
		"org.springframework.security.saml2.spi.keycloak.KeycloakSaml2Transformer";

	private static Log logger = LogFactory.getLog(Saml2ServiceProviderConfiguration.class);

	private HttpSecurity http;
	private Saml2Transformer transformer;
	private Saml2ServiceProviderValidator validator;
	private Saml2ServiceProviderMetadataResolver metadataResolver;
	private Saml2ServiceProviderResolver providerResolver;
	private Saml2ServiceProviderConfigurationResolver configurationResolver;
	private AuthenticationFailureHandler failureHandler;
	private AuthenticationManager authenticationManager;
	private AuthenticationEntryPoint authenticationEntryPoint;
	private String pathPrefix;
	private ClassLoader classLoader = Saml2ServiceProviderConfiguration.class.getClassLoader();

	Saml2ServiceProviderConfiguration() {
	}

	Saml2ServiceProviderConfiguration setProviderResolver(Saml2ServiceProviderResolver resolver) {
		notNull(resolver, "providerResolver must not be null");
		isNull(configurationResolver, "configurationResolver", "providerResolver");
		this.providerResolver = resolver;
		return this;
	}

	Saml2ServiceProviderConfiguration setAuthenticationManager(AuthenticationManager manager) {
		notNull(manager, "authenticationManager must not be null");
		this.authenticationManager = manager;
		return this;
	}

	Saml2ServiceProviderConfiguration setConfigurationResolver(Saml2ServiceProviderConfigurationResolver resolver) {
		notNull(resolver, "configurationResolver must not be null");
		isNull(providerResolver, "providerResolver", "configurationResolver");
		this.configurationResolver = resolver;
		return this;
	}

	Saml2ServiceProviderConfiguration authenticationFailureHandler(AuthenticationFailureHandler handler) {
		notNull(handler, "authenticationFailureHandler must not be null");
		this.failureHandler = handler;
		return this;
	}

	Saml2ServiceProviderConfiguration validate(HttpSecurity http) {
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

	Saml2ServiceProviderMethods getServiceProviderMethods() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2ServiceProviderMethods.class,
			() -> new Saml2ServiceProviderMethods(
				transformer,
				providerResolver,
				validator
			),
			null
		);
	}

	Saml2HttpMessageResponder getSamlHttpMessageResponder() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2HttpMessageResponder.class,
			() ->
				new Saml2HttpMessageResponder(
					new Saml2ServiceProviderMethods(
						transformer,
						providerResolver,
						validator
					),
					new DefaultRedirectStrategy()
				),
			null
		);
	}

	Filter getLogoutFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2ServiceProviderLogoutFilter.class,
			() -> {
				SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
				logoutSuccessHandler.setDefaultTargetUrl(pathPrefix + "/select");
				return new Saml2ServiceProviderLogoutFilter(
					getServiceProviderMethods(),
					getSamlHttpMessageResponder(),
					new AntPathRequestMatcher(pathPrefix + "/logout/**")
				)
					.setLogoutSuccessHandler(logoutSuccessHandler);
			},
			null
		);
	}

	Filter getWebSsoAuthenticationFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		Saml2WebSsoAuthenticationFilter filter = getSharedObject(
			http,
			Saml2WebSsoAuthenticationFilter.class,
			() -> new Saml2WebSsoAuthenticationFilter(
				getServiceProviderMethods(),
				new AntPathRequestMatcher(pathPrefix + "/SSO/**")
			),
			null
		);
		filter.setAuthenticationManager(getAuthenticationManager());
		filter.setAuthenticationFailureHandler(getAuthenticationFailureHandler());
		return filter;
	}

	Filter getAuthenticationRequestFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2AuthenticationRequestFilter.class,
			() -> new Saml2AuthenticationRequestFilter(
				new DefaultSaml2AuthenticationRequestResolver(getServiceProviderMethods()),
				getSamlHttpMessageResponder(),
				new AntPathRequestMatcher(pathPrefix + "/authenticate/**")
			),
			null
		);
	}

	Filter getStaticLoginPageFilter() {
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

	Filter getMetadataFilter() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		return getSharedObject(
			http,
			Saml2ServiceProviderMetadataFilter.class,
			() -> new Saml2ServiceProviderMetadataFilter(
				providerResolver,
				transformer,
				new AntPathRequestMatcher(pathPrefix + "/metadata/**")
			),
			null
		);
	}

	AuthenticationFailureHandler getAuthenticationFailureHandler() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		failureHandler = ofNullable(failureHandler)
			.orElseGet(() -> new Saml2AuthenticationFailureHandler());
		return failureHandler;
	}

	Saml2ServiceProviderResolver getServiceProviderResolver() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		providerResolver = getSharedObject(
			http,
			Saml2ServiceProviderResolver.class,
			() -> null,
			providerResolver
		);
		return providerResolver;
	}

	Saml2ServiceProviderMetadataResolver getSamlMetadataResolver() {
		notNull(this.http, "Call validate(HttpSecurity) first.");
		metadataResolver = getSharedObject(
			http,
			Saml2ServiceProviderMetadataResolver.class,
			() -> new DefaultSaml2ServiceProviderMetadataResolver(transformer),
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
		final Saml2ServiceProviderConfigurationResolver configResolver = getSharedObject(
			http,
			Saml2ServiceProviderConfigurationResolver.class,
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
				Saml2ServiceProviderResolver.class.getName() + ".getConfiguredPathPrefix() must not return null"
			);
		}
		else {
			//do we have a configurationResolver?
			configurationResolver = getSharedObject(
				http,
				Saml2ServiceProviderConfigurationResolver.class,
				null,
				configurationResolver
			);

			notNull(
				configurationResolver,
				Saml2ServiceProviderConfigurationResolver.class.getName() + " must not be null"
			);

			notNull(
				configurationResolver.getConfiguredPathPrefix(),
				Saml2ServiceProviderConfigurationResolver.class.getName() +
					".getConfiguredPathPrefix() must not return null"
			);

			metadataResolver = getSamlMetadataResolver();
			providerResolver = new DefaultSaml2ServiceProviderResolver(metadataResolver, configurationResolver);
			setSharedObject(http, Saml2ServiceProviderResolver.class, providerResolver);
		}
	}


	private Saml2Transformer createDefaultSamlTransformer() {
		try {
			return getClassInstance(SAML2_TRANSFORMER_OPEN_SAML);
		} catch (Saml2Exception e) {
			try {
				return getClassInstance(SAML2_TRANSFORMER_KEYCLOAK);
			} catch (Saml2Exception e2) {
				throw e;
			}
		}
	}

	Saml2Transformer getClassInstance(String className) {
		try {
			logger.info("Loading SAML2 implementation:" + className);
			Class<?> clazz = Class.forName(className, true, classLoader);
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

	@Override
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.classLoader = classLoader;
	}


}
