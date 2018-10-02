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

package org.springframework.security.saml.provider.identity.config;

import java.util.LinkedList;
import java.util.List;
import javax.servlet.Filter;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

public class SamlIdentityProviderSecurityDsl
	extends AbstractHttpConfigurer<SamlIdentityProviderSecurityDsl, HttpSecurity> {

	private String prefix = "saml/idp/";
	private boolean useStandardFilterConfiguration = true;
	private List<Filter> filters = new LinkedList<>();
	private SamlServerConfiguration configuration = new SamlServerConfiguration(
		null,
		null,
		null
	);
//		.setNetwork(
//			new NetworkConfiguration(readTimeout, connectTimeout)
//				.setConnectTimeout(5000)
//				.setReadTimeout(10000)
//		)
//		.setIdentityProvider(
//			new LocalIdentityProviderConfiguration()
//				.setPrefix(prefix)
//				.setSignMetadata(true)
//				.setSignAssertions(true)
//				.setWantRequestsSigned(true)
//				.setDefaultSigningAlgorithm(RSA_SHA256)
//				.setDefaultDigest(SHA256)
//				.setNameIds(
//					asList(
//						PERSISTENT,
//						EMAIL,
//						UNSPECIFIED
//					)
//				)
//				.setEncryptAssertions(false)
//				.setKeyEncryptionAlgorithm(RSA_1_5)
//				.setProviders(new LinkedList<>())
//		)

	@Override
	public void configure(HttpSecurity http) throws Exception {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		SamlServerConfiguration serverConfig = context.getBean("idpSamlServerConfiguration",SamlServerConfiguration.class);
		serverConfig.transfer(this.configuration);

		if (useStandardFilterConfiguration) {
			SamlIdentityProviderServerBeanConfiguration beanConfig =
				context.getBean(SamlIdentityProviderServerBeanConfiguration.class);
			Filter samlConfigurationFilter = beanConfig.samlConfigurationFilter();
			Filter metadataFilter = beanConfig.idpMetadataFilter();
			Filter idpInitiateLoginFilter = beanConfig.idpInitatedLoginFilter();
			Filter idpAuthnRequestFilter = beanConfig.idpAuthnRequestFilter();
			Filter idpLogoutFilter = beanConfig.idpLogoutFilter();
			http
				.addFilterAfter(
					samlConfigurationFilter,
					SecurityContextPersistenceFilter.class
				)
				.addFilterAfter(
					metadataFilter,
					samlConfigurationFilter.getClass()
				)
				.addFilterAfter(
					idpInitiateLoginFilter,
					metadataFilter.getClass()
				)
				.addFilterAfter(
					idpAuthnRequestFilter,
					idpInitiateLoginFilter.getClass()
				)
				.addFilterAfter(
					idpLogoutFilter,
					idpAuthnRequestFilter.getClass()
				)
				.addFilterAfter(
					beanConfig.idpSelectServiceProviderFilter(),
					idpLogoutFilter.getClass()
				);
		}
	}

	public SamlIdentityProviderSecurityDsl configure(SamlServerConfiguration config) {
		this.configuration = config;
		return this;
	}

	public SamlIdentityProviderSecurityDsl prefix(String prefix) {
//		configuration.getIdentityProvider().setPrefix(prefix);
		this.prefix = prefix;
		return this;
	}

	public SamlIdentityProviderSecurityDsl entityId(String entityId) {
//		configuration.getIdentityProvider().setEntityId(entityId);
		return this;
	}

	public SamlIdentityProviderSecurityDsl alias(String alias) {
//		configuration.getIdentityProvider().setAlias(alias);
		return this;
	}

	public SamlIdentityProviderSecurityDsl signMetadata(boolean sign) {
//		configuration.getIdentityProvider().setSignMetadata(sign);
		return this;
	}

	public SamlIdentityProviderSecurityDsl signatureAlgorithms(AlgorithmMethod signAlgorithm,
															   DigestMethod signDigest) {
//		configuration.getIdentityProvider()
//			.setDefaultSigningAlgorithm(signAlgorithm)
//			.setDefaultDigest(signDigest);
		return this;
	}

	public SamlIdentityProviderSecurityDsl signAssertions(boolean sign) {
//		configuration.getIdentityProvider()
//			.setSignAssertions(sign);
		return this;
	}

	public SamlIdentityProviderSecurityDsl wantRequestsSigned(boolean sign) {
//		configuration.getIdentityProvider()
//			.setWantRequestsSigned(sign);
		return this;
	}

	public SamlIdentityProviderSecurityDsl encryptAssertions(boolean encrypt,
															 KeyEncryptionMethod keyEncryptionAlgorithm,
															 DataEncryptionMethod dataEncryptionAlgorithm) {
//		configuration.getIdentityProvider()
//			.setEncryptAssertions(encrypt)
//			.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm)
//			.setDataEncryptionAlgorithm(dataEncryptionAlgorithm);
		return this;
	}

	public SamlIdentityProviderSecurityDsl singleLogout(boolean enabled) {
//		configuration.getIdentityProvider()
//			.setSingleLogoutEnabled(enabled);
		return this;
	}

	public SamlIdentityProviderSecurityDsl nameIds(List<NameId> nameIds) {
//		configuration.getIdentityProvider()
//			.setNameIds(nameIds);
		return this;
	}

	public SamlIdentityProviderSecurityDsl keys(List<SimpleKey> keys) {
//		configuration.getIdentityProvider()
//			.setKeys(keys);
		return this;
	}

	public SamlIdentityProviderSecurityDsl serviceProvider(ExternalServiceProviderConfiguration sp) {
//		this.configuration.getIdentityProvider().getProviders().add(sp);
		return this;
	}

	public SamlIdentityProviderSecurityDsl useStandardFilters() {
		return useStandardFilters(true);
	}

	public SamlIdentityProviderSecurityDsl useStandardFilters(boolean enable) {
		this.useStandardFilterConfiguration = enable;
		return this;
	}

	public SamlIdentityProviderSecurityDsl filters(List<Filter> filters) {
		this.filters.clear();
		this.filters.addAll(filters);
		return this;
	}


	public static SamlIdentityProviderSecurityDsl identityProvider() {
		return new SamlIdentityProviderSecurityDsl();
	}

}
