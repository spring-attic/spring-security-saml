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
import org.springframework.security.saml.provider.identity.HostedIdentityProviderService;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.util.StringUtils.hasText;

public class HostBasedSamlIdentityProviderProvisioning
	extends AbstractHostbasedSamlProviderProvisioning
	implements SamlProviderProvisioning<IdentityProviderService> {


	public HostBasedSamlIdentityProviderProvisioning(SamlConfigurationRepository configuration,
													 SamlTransformer transformer,
													 SamlValidator validator,
													 SamlMetadataCache cache) {
		super(configuration, transformer, validator, cache);
	}


	@Override
	public IdentityProviderService getHostedProvider(HttpServletRequest request) {
		String basePath = getBasePath(request);
		LocalIdentityProviderConfiguration idpConfig =
			getConfiguration().getServerConfiguration(request).getIdentityProvider();

		List<SimpleKey> keys = new LinkedList<>();
		keys.add(idpConfig.getKeys().getActive());
		keys.addAll(idpConfig.getKeys().getStandBy());
		SimpleKey signingKey = idpConfig.isSignMetadata() ? idpConfig.getKeys().getActive() : null;

		String prefix = hasText(idpConfig.getPrefix()) ? idpConfig.getPrefix() : "saml/idp/";
		String aliasPath = getAliasPath(idpConfig);
		IdentityProviderMetadata metadata =
			identityProviderMetadata(
				basePath,
				signingKey,
				keys,
				prefix,
				aliasPath,
				idpConfig.getDefaultSigningAlgorithm(),
				idpConfig.getDefaultDigest()
			);

		if (!idpConfig.getNameIds().isEmpty()) {
			metadata.getIdentityProvider().setNameIds(idpConfig.getNameIds());
		}

		if (!idpConfig.isSingleLogoutEnabled()) {
			metadata.getIdentityProvider().setSingleLogoutService(Collections.emptyList());
		}
		if (hasText(idpConfig.getEntityId())) {
			metadata.setEntityId(idpConfig.getEntityId());
		}
		if (hasText(idpConfig.getAlias())) {
			metadata.setEntityAlias(idpConfig.getAlias());
		}

		metadata.getIdentityProvider().setWantAuthnRequestsSigned(idpConfig.isWantRequestsSigned());

		return new HostedIdentityProviderService(
			idpConfig,
			metadata,
			getTransformer(),
			getValidator(),
			getCache()
		);
	}

	private IdentityProviderMetadata identityProviderMetadata(String baseUrl,
															  SimpleKey signingKey,
															  List<SimpleKey> keys,
															  String prefix,
															  String aliasPath,
															  AlgorithmMethod signAlgorith,
															  DigestMethod signDigest) {

		return new IdentityProviderMetadata()
			.setEntityId(baseUrl)
			.setId(UUID.randomUUID().toString())
			.setSigningKey(signingKey, signAlgorith, signDigest)
			.setProviders(
				asList(
					new org.springframework.security.saml.saml2.metadata.IdentityProvider()
						.setWantAuthnRequestsSigned(true)
						.setSingleSignOnService(
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
