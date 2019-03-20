/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.provider.provisioning;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.identity.AssertionEnhancer;
import org.springframework.security.saml.provider.identity.HostedIdentityProviderService;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.ResponseEnhancer;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;

import static org.springframework.util.StringUtils.hasText;

public class HostBasedSamlIdentityProviderProvisioning
	extends AbstractHostbasedSamlProviderProvisioning
	implements SamlProviderProvisioning<IdentityProviderService> {


	private AssertionEnhancer assertionEnhancer;
	private ResponseEnhancer responseEnhancer;

	public HostBasedSamlIdentityProviderProvisioning(SamlConfigurationRepository configuration,
													 SamlTransformer transformer,
													 SamlValidator validator,
													 SamlMetadataCache cache,
													 AssertionEnhancer assertionEnhancer,
													 ResponseEnhancer responseEnhancer) {
		super(configuration, transformer, validator, cache);
		this.assertionEnhancer = assertionEnhancer;
		this.responseEnhancer = responseEnhancer;
	}


	@Override
	public IdentityProviderService getHostedProvider() {
		LocalIdentityProviderConfiguration config =
			getConfigurationRepository().getServerConfiguration().getIdentityProvider();
		return getHostedIdentityProvider(config);
	}

	@Override
	protected IdentityProviderService getHostedIdentityProvider(LocalIdentityProviderConfiguration idpConfig) {
		String basePath = idpConfig.getBasePath();
		List<SimpleKey> keys = new LinkedList<>();
		SimpleKey activeKey = idpConfig.getKeys().getActive();
		keys.add(activeKey);
		keys.add(activeKey.clone(activeKey.getName()+"-encryption", KeyType.ENCRYPTION));
		keys.addAll(idpConfig.getKeys().getStandBy());
		SimpleKey signingKey = idpConfig.isSignMetadata() ? activeKey : null;

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
			getCache(),
			assertionEnhancer,
			responseEnhancer
		);
	}


}

