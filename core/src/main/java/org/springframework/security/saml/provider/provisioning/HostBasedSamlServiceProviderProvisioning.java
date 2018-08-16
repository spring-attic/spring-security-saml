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

package org.springframework.security.saml.provider.provisioning;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.service.HostedServiceProviderService;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.util.StringUtils.hasText;

public class HostBasedSamlServiceProviderProvisioning
	extends AbstractHostbasedSamlProviderProvisioning
	implements SamlProviderProvisioning<ServiceProviderService> {

	public HostBasedSamlServiceProviderProvisioning(SamlConfigurationRepository configuration,
													SamlTransformer transformer,
													SamlValidator validator,
													SamlMetadataCache cache) {
		super(configuration, transformer, validator, cache);
	}


	@Override
	public ServiceProviderService getHostedProvider(HttpServletRequest request) {
		String basePath = getBasePath(request);
		LocalServiceProviderConfiguration spConfig =
			getConfiguration().getServerConfiguration(request).getServiceProvider();

		List<SimpleKey> keys = new LinkedList<>();
		keys.add(spConfig.getKeys().getActive());
		keys.addAll(spConfig.getKeys().getStandBy());
		SimpleKey signingKey = spConfig.isSignMetadata() ? spConfig.getKeys().getActive() : null;

		String prefix = hasText(spConfig.getPrefix()) ? spConfig.getPrefix() : "saml/sp/";
		String aliasPath = getAliasPath(spConfig);
		ServiceProviderMetadata metadata =
			serviceProviderMetadata(
				basePath,
				signingKey,
				keys,
				prefix,
				aliasPath,
				spConfig.getDefaultSigningAlgorithm(),
				spConfig.getDefaultDigest()
			);
		if (!spConfig.getNameIds().isEmpty()) {
			metadata.getServiceProvider().setNameIds(spConfig.getNameIds());
		}

		if (!spConfig.isSingleLogoutEnabled()) {
			metadata.getServiceProvider().setSingleLogoutService(Collections.emptyList());
		}
		if (hasText(spConfig.getEntityId())) {
			metadata.setEntityId(spConfig.getEntityId());
		}
		if (hasText(spConfig.getAlias())) {
			metadata.setEntityAlias(spConfig.getAlias());
		}
		metadata.getServiceProvider().setWantAssertionsSigned(spConfig.isWantAssertionsSigned());
		metadata.getServiceProvider().setAuthnRequestsSigned(spConfig.isSignRequests());

		return new HostedServiceProviderService(
			spConfig,
			metadata,
			getTransformer(),
			getValidator(),
			getCache()
		);
	}

	protected ServiceProviderMetadata serviceProviderMetadata(String baseUrl,
															  SimpleKey signingKey,
															  List<SimpleKey> keys,
															  String prefix,
															  String aliasPath,
															  AlgorithmMethod signAlgorithm,
															  DigestMethod signDigest) {

		return new ServiceProviderMetadata()
			.setEntityId(baseUrl)
			.setId(UUID.randomUUID().toString())
			.setSigningKey(signingKey, signAlgorithm, signDigest)
			.setProviders(
				asList(
					new org.springframework.security.saml.saml2.metadata.ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(true)
						.setAuthnRequestsSigned(signingKey != null)
						.setAssertionConsumerService(
							asList(
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, Binding.POST, 0, true),
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)
							)
						)
						.setNameIds(asList(NameId.PERSISTENT, NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(baseUrl, prefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)
							)
						)
				)
			);

	}

}
