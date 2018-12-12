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

import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.GenericBeanDefinition;
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

import static java.util.Arrays.asList;
import static java.util.Optional.ofNullable;
import static org.springframework.beans.factory.config.BeanDefinition.SCOPE_SINGLETON;
import static org.springframework.util.Assert.notNull;

public class SamlServiceProviderConfigurer extends AbstractHttpConfigurer<SamlServiceProviderConfigurer, HttpSecurity> {

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
	 * Required fields - mutually exclusive
	 */
	private ServiceProviderResolver providerResolver = null;
	private ServiceProviderConfigurationResolver configurationResolver;

	/*
	 * Fields with implementation defaults
	 */
	private SamlTransformer samlTransformer = null;
	private ServiceProviderValidator samlValidator = null;
	private SamlTemplateEngine samlTemplateEngine = null;
	private AuthenticationManager authenticationManager = null;
	private ServiceProviderMetadataResolver metadataResolver = null;
	private HtmlWriter htmlTemplateProcessor;
	private AuthenticationFailureHandler failureHandler;

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
		isNull(providerResolver, "providerResolver", "configurationResolver");
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
		isNull(configurationResolver, "configurationResolver", "providerResolver");
		this.providerResolver = resolver;
		return this;
	}

	/*
	 * Configuration
	 */
	@Override
	public void init(HttpSecurity http) throws Exception {
		samlTransformer = getSamlTransformer(http, samlTransformer);
		samlValidator = getSamlValidator(http, samlTransformer, samlValidator);
		samlTemplateEngine = getSamlTemplateEngine(http, samlTemplateEngine);
		metadataResolver = getSamlMetadataResolver(http, samlTransformer, metadataResolver);
		providerResolver = getServiceProviderResolver(http, providerResolver);
		htmlTemplateProcessor = getHtmlTemplateWriter(samlTemplateEngine);
		failureHandler = getAuthenticationFailureHandler(htmlTemplateProcessor);

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
			Filter metadataFilter = getMetadataFilter(http, pathPrefix, samlTransformer);
			Filter selectIdentityProviderFilter = getSelectIdentityProviderFilter(
				http, pathPrefix, htmlTemplateProcessor
			);
			Filter authenticationRequestFilter = getIdentityProviderDiscoveryFilter(
				http, pathPrefix, samlTransformer,htmlTemplateProcessor
			);
			AbstractAuthenticationProcessingFilter authenticationFilter = getWebSsoAuthenticationFilter(
				http, pathPrefix, samlValidator
			);
			authenticationFilter.setAuthenticationManager(ofNullable(authenticationManager).orElseGet(() -> a -> a));
			authenticationFilter.setAuthenticationFailureHandler(failureHandler);
			Filter logoutFilter = getLogoutFilter(http, pathPrefix, samlTransformer, samlValidator);
			SamlProcessingFilter processingFilter = getSamlProcessingFilter(pathPrefix, samlTransformer,
				providerResolver, samlValidator
			);

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

	private SamlProcessingFilter getSamlProcessingFilter(String pathPrefix,
														 SamlTransformer transformer,
														 ServiceProviderResolver resolver,
														 ServiceProviderValidator validator) {
		return new SamlProcessingFilter(
			transformer,
			resolver,
			validator,
			new AntPathRequestMatcher(pathPrefix + "/**")
		);
	}

	private ServiceProviderLogoutFilter getLogoutFilter(HttpSecurity http,
														String pathPrefix,
														SamlTransformer transformer,
														ServiceProviderValidator validator) {
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

	private SamlWebSsoAuthenticationFilter getWebSsoAuthenticationFilter(HttpSecurity http,
																		 String pathPrefix,
																		 ServiceProviderValidator validator) {
		return getSharedObject(
			http,
			SamlWebSsoAuthenticationFilter.class,
			() -> new SamlWebSsoAuthenticationFilter(
				new AntPathRequestMatcher(pathPrefix + "/SSO/**"),
				validator
			),
			null
		);
	}

	private SamlAuthenticationRequestFilter getIdentityProviderDiscoveryFilter(HttpSecurity http,
																			   String pathPrefix,
																			   SamlTransformer transformer,
																			   HtmlWriter htmlWriter) {
		return getSharedObject(
			http,
			SamlAuthenticationRequestFilter.class,
			() -> new SamlAuthenticationRequestFilter(
				new AntPathRequestMatcher(pathPrefix + "/discovery/**"),
				transformer,
				htmlWriter
			),
			null
		);
	}

	private SelectIdentityProviderUIFilter getSelectIdentityProviderFilter(HttpSecurity http,
																		   String pathPrefix,
																		   HtmlWriter htmlWriter) {
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

	private SamlServiceProviderMetadataFilter getMetadataFilter(HttpSecurity http,
																String pathPrefix, SamlTransformer transformer) {
		return getSharedObject(
			http,
			SamlServiceProviderMetadataFilter.class,
			() -> new SamlServiceProviderMetadataFilter(
				new AntPathRequestMatcher(pathPrefix + "/metadata/**"),
				transformer
			),
			null
		);
	}

	private AuthenticationFailureHandler getAuthenticationFailureHandler(HtmlWriter htmlWriter) {
		return new SamlAuthenticationFailureHandler(htmlWriter);
	}

	private HtmlWriter getHtmlTemplateWriter(SamlTemplateEngine templateEngine) {
		return new HtmlWriter(templateEngine);
	}

	private ServiceProviderResolver getServiceProviderResolver(HttpSecurity http, ServiceProviderResolver resolver) {
		return getSharedObject(
			http,
			ServiceProviderResolver.class,
			() -> null,
			resolver
		);
	}

	private ServiceProviderMetadataResolver getSamlMetadataResolver(HttpSecurity http,
																	SamlTransformer transformer,
																	ServiceProviderMetadataResolver metadataResolver) {
		return getSharedObject(
			http,
			ServiceProviderMetadataResolver.class,
			() -> new DefaultServiceProviderMetadataResolver(transformer),
			metadataResolver
		);
	}

	private SamlTemplateEngine getSamlTemplateEngine(HttpSecurity http, SamlTemplateEngine templateEngine) {
		return getSharedObject(
			http,
			SamlTemplateEngine.class,
			() -> new VelocityTemplateEngine(true),
			templateEngine
		);
	}

	private ServiceProviderValidator getSamlValidator(HttpSecurity http,
													  SamlTransformer transformer, ServiceProviderValidator validator) {
		return getSharedObject(
			http,
			ServiceProviderValidator.class,
			() -> new DefaultServiceProviderValidator(transformer),
			validator
		);
	}

	private SamlTransformer getSamlTransformer(HttpSecurity http, SamlTransformer transformer) {
		return getSharedObject(
			http,
			SamlTransformer.class,
			this::createDefaultSamlTransformer,
			transformer
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

	private void isNull(Object configuredObject, String identifier, String alternate) {
		if (ofNullable(configuredObject).isPresent()) {
			throw new IllegalStateException(identifier +" should be null if you wish to configure a "+ alternate);
		}
	}

	/*
	 * ================== INITIALIZATION STATE==================
	 * Avoid setting up multiple SAML filters
	 */

	private boolean isPreviouslyInitialized(HttpSecurity http) {
		return getConfigurationState(http) != SharedConfigurationState.NOT_INITIALIZED;
	}

	private void setInitializationCompleted(HttpSecurity http) {
		setConfigurationState(http, SharedConfigurationState.INITIALIZED);
	}

	private boolean isPreviouslyConfigured(HttpSecurity http) {
		return getConfigurationState(http) == SharedConfigurationState.CONFIGURED;
	}

	private void setConfigurationCompleted(HttpSecurity http) {
		setConfigurationState(http, SharedConfigurationState.CONFIGURED);
	}

	private SharedConfigurationState getConfigurationState(HttpSecurity http) {
		BeanDefinition definition = getConfigurationStateBeanDefinition(http);
		return (SharedConfigurationState) definition.getPropertyValues().get(SharedConfigurationState.class.getName());
	}

	private void setConfigurationState(HttpSecurity http, SharedConfigurationState state) {
		BeanDefinition definition = getConfigurationStateBeanDefinition(http);
		((GenericBeanDefinition)definition).setPropertyValues(getStatePropertyValues(state));
	}

	private BeanDefinition getConfigurationStateBeanDefinition(HttpSecurity http) {
		ApplicationContext context = getSharedObject(http, ApplicationContext.class);
		AutowireCapableBeanFactory beanFactory = context.getAutowireCapableBeanFactory();
		BeanDefinitionRegistry registry = (BeanDefinitionRegistry)beanFactory;
		BeanDefinition definition = null;
		try {
			definition = registry.getBeanDefinition(SharedConfigurationState.class.getName());
		} catch (NoSuchBeanDefinitionException e) {
			definition = getStateBean(SharedConfigurationState.NOT_INITIALIZED);
			registry.registerBeanDefinition(SharedConfigurationState.class.getName(), definition);
		}
		return definition;
	}

	private GenericBeanDefinition getStateBean(SharedConfigurationState state) {
		GenericBeanDefinition definition = new GenericBeanDefinition();
		definition.setBeanClass(SharedConfigurationState.class);
		definition.setScope(SCOPE_SINGLETON);
		MutablePropertyValues values = getStatePropertyValues(state);
		definition.setPropertyValues(values);
		return definition;
	}

	private MutablePropertyValues getStatePropertyValues(SharedConfigurationState state) {
		PropertyValue stateValue = new PropertyValue(SharedConfigurationState.class.getName(),state);
		return new MutablePropertyValues(asList(stateValue));
	}

	private enum SharedConfigurationState {
		NOT_INITIALIZED,
		INITIALIZED,
		CONFIGURED
	}

}
