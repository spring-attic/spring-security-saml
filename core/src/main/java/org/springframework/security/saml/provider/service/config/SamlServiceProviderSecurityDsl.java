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

package org.springframework.security.saml.provider.service.config;

import java.util.List;
import javax.servlet.Filter;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml.saml2.key.SimpleKey;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public class SamlServiceProviderSecurityDsl
	extends AbstractHttpConfigurer<SamlServiceProviderSecurityDsl, HttpSecurity> {

	private String prefix = "saml/sp/";

	@Override
	public void init(HttpSecurity builder) throws Exception {
		super.init(builder);
		String antPattern = "/" + stripSlashes(prefix);
		builder.antMatcher(antPattern + "/**")
			.csrf().disable()
			.authorizeRequests()
			.antMatchers(antPattern + "/**").permitAll();
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		SamlServiceProviderServerBeanConfiguration spBeanConfig =
			context.getBean(SamlServiceProviderServerBeanConfiguration.class);
		Filter samlConfigurationFilter = spBeanConfig.samlConfigurationFilter();
		Filter metadataFilter = spBeanConfig.spMetadataFilter();
		Filter spAuthenticationRequestFilter = spBeanConfig.spAuthenticationRequestFilter();
		Filter spAuthenticationResponseFilter = spBeanConfig.spAuthenticationResponseFilter();
		Filter spSamlLogoutFilter = spBeanConfig.spSamlLogoutFilter();
		Filter spSelectIdentityProviderFilter = spBeanConfig.spSelectIdentityProviderFilter();
		http
			.addFilterAfter(
				samlConfigurationFilter,
				BasicAuthenticationFilter.class
			)
			.addFilterAfter(
				metadataFilter,
				samlConfigurationFilter.getClass()
			)
			.addFilterAfter(
				spAuthenticationRequestFilter,
				metadataFilter.getClass()
			)
			.addFilterAfter(
				spAuthenticationResponseFilter,
				spAuthenticationRequestFilter.getClass()
			)
			.addFilterAfter(
				spSamlLogoutFilter,
				spAuthenticationResponseFilter.getClass()
			)
			.addFilterAfter(
				spSelectIdentityProviderFilter,
				spSamlLogoutFilter.getClass()
			);

	}

	public SamlServiceProviderSecurityDsl prefix(String prefix) {
//		configuration.getServiceProvider().setPrefix(prefix);
		this.prefix = prefix;
		return this;
	}

	public SamlServiceProviderSecurityDsl entityId(String entityId) {
//		configuration.getServiceProvider().setEntityId(entityId);
		return this;
	}

	public SamlServiceProviderSecurityDsl alias(String alias) {
//		configuration.getServiceProvider().setAlias(alias);
		return this;
	}

	public SamlServiceProviderSecurityDsl signMetadata(boolean sign) {
//		configuration.getServiceProvider().setSignMetadata(sign);
		return this;
	}

	public SamlServiceProviderSecurityDsl signRequests(boolean sign) {
//		configuration.getServiceProvider().setSignRequests(sign);
		return this;
	}

	public SamlServiceProviderSecurityDsl wantAssertionsSigned(boolean sign) {
//		configuration.getServiceProvider().setWantAssertionsSigned(sign);
		return this;
	}

	public SamlServiceProviderSecurityDsl signatureAlgorithms(AlgorithmMethod signAlgorithm,
															  DigestMethod signDigest) {
//		configuration.getServiceProvider()
//			.setDefaultSigningAlgorithm(signAlgorithm)
//			.setDefaultDigest(signDigest);
		return this;
	}

	public SamlServiceProviderSecurityDsl singleLogout(boolean enabled) {
//		configuration.getServiceProvider()
//			.setSingleLogoutEnabled(enabled);
		return this;
	}

	public SamlServiceProviderSecurityDsl nameIds(List<NameId> nameIds) {
//		configuration.getServiceProvider()
//			.setNameIds(nameIds);
		return this;
	}

	public SamlServiceProviderSecurityDsl keys(List<SimpleKey> keys) {
//		configuration.getServiceProvider()
//			.setKeys(keys);
		return this;
	}

	public static SamlServiceProviderSecurityDsl serviceProvider() {
		return new SamlServiceProviderSecurityDsl();
	}

}
