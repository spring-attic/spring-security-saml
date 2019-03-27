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

package org.springframework.security.saml2.serviceprovider.metadata;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.saml2.Saml2MetadataCache;
import org.springframework.security.saml2.Saml2ProviderNotFoundException;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.configuration.ExternalSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2ProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProvider;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2Metadata;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml2.model.metadata.SsoProvider;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.security.saml2.serviceprovider.web.cache.DefaultSaml2MetadataCache;
import org.springframework.security.saml2.serviceprovider.web.cache.RestOperationsUtils;
import org.springframework.security.saml2.util.Saml2StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;
import static org.springframework.security.saml2.model.metadata.Saml2Binding.REDIRECT;
import static org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod.RSA_SHA256;
import static org.springframework.security.saml2.model.signature.Saml2DigestMethod.SHA256;
import static org.springframework.security.saml2.util.Saml2StringUtils.isUrl;
import static org.springframework.security.saml2.util.Saml2StringUtils.stripSlashes;
import static org.springframework.security.saml2.util.Saml2StringUtils.stripStartingSlashes;
import static org.springframework.util.StringUtils.hasText;

public class DefaultServiceProviderMetadataResolver implements ServiceProviderMetadataResolver {
	private static Log logger = LogFactory.getLog(DefaultServiceProviderMetadataResolver.class);

	private final Saml2Transformer saml2Transformer;

	private Saml2MetadataCache cache = new DefaultSaml2MetadataCache(
		Clock.systemUTC(),
		new RestOperationsUtils(4000, 4000).get(false),
		new RestOperationsUtils(4000, 4000).get(true)
	);

	public DefaultServiceProviderMetadataResolver(Saml2Transformer saml2Transformer) {
		this.saml2Transformer = saml2Transformer;
	}

	public DefaultServiceProviderMetadataResolver setCache(Saml2MetadataCache cache) {
		this.cache = cache;
		return this;
	}

	@Override
	public ServiceProviderMetadata getMetadata(HostedSaml2ServiceProviderConfiguration configuration) {
		return generateMetadata(configuration);
	}

	@Override
	public Map<ExternalSaml2IdentityProviderConfiguration, Saml2IdentityProviderMetadata> getIdentityProviders(
		HostedSaml2ServiceProviderConfiguration configuration
	) {
		return getProviders(configuration);
	}

	private Map<ExternalSaml2IdentityProviderConfiguration, Saml2IdentityProviderMetadata> getProviders(
		HostedSaml2ServiceProviderConfiguration configuration) {
		Map<ExternalSaml2IdentityProviderConfiguration, Saml2IdentityProviderMetadata> result = new HashMap<>();
		List<ExternalSaml2IdentityProviderConfiguration> providers = configuration.getProviders();
		for (ExternalSaml2IdentityProviderConfiguration idpConfig : providers) {
			Saml2IdentityProviderMetadata idp = getIdentityProviderMetadata(idpConfig);
			idp = metadataTrustCheck(idpConfig, idp);
			if (idp != null) {
				result.put(idpConfig, idp);
			}
		}
		return result;
	}

	private Saml2IdentityProviderMetadata metadataTrustCheck(ExternalSaml2IdentityProviderConfiguration idpConfig,
															 Saml2IdentityProviderMetadata idp) {
		if (!idpConfig.isMetadataTrustCheck()) {
			return idp;
		}
		if (idpConfig.getVerificationKeys().isEmpty()) {
			logger.warn("No keys to verify metadata for " + idpConfig.getMetadata() + " with. Unable to trust.");
			return null;
		}
		try {
			Saml2Signature signature = saml2Transformer.validateSignature(idp, idpConfig.getVerificationKeys());
			if (signature != null &&
				signature.isValidated() &&
				signature.getValidatingKey() != null) {
				return idp;
			}
			else {
				logger.warn("Missing signature for " + idpConfig.getMetadata() + ". Unable to trust.");
			}
		} catch (Saml2SignatureException e) {
			logger.warn("Invalid signature for IDP metadata " + idpConfig.getMetadata() + ". Unable to trust.", e);
		}
		return null;
	}

	private Saml2IdentityProviderMetadata getIdentityProviderMetadata(ExternalSaml2IdentityProviderConfiguration idp) {
		Saml2IdentityProviderMetadata result = null;
		try {
			byte[] data = idp.getMetadata().getBytes(StandardCharsets.UTF_8);
			if (isUri(idp.getMetadata())) {
				data = cache.getMetadata(idp.getMetadata(), idp.isSkipSslValidation());
			}
			Saml2Metadata metadata = (Saml2Metadata) saml2Transformer.fromXml(data, null, null);
			metadata.setEntityAlias(idp.getAlias());
			result = transform(metadata);
			addStaticKeys(idp, result);
		} catch (Saml2ProviderNotFoundException e) {
			logger.debug("Unable to resolve remote metadata:" + e.getMessage());
		}
		return result;
	}

	private void addStaticKeys(ExternalSaml2IdentityProviderConfiguration idp, Saml2IdentityProviderMetadata metadata) {
		if (!idp.getVerificationKeys().isEmpty() && metadata != null) {
			List<Saml2KeyData> keys = new LinkedList(metadata.getIdentityProvider().getKeys());
			keys.addAll(idp.getVerificationKeys());
			metadata.getIdentityProvider().setKeys(keys);
		}
	}

	private Saml2IdentityProviderMetadata transform(Saml2Metadata metadata) {
		if (metadata instanceof Saml2IdentityProviderMetadata) {
			return (Saml2IdentityProviderMetadata) metadata;
		}
		else {
			List<SsoProvider> providers = metadata.getSsoProviders();
			providers = providers.stream().filter(p -> p instanceof Saml2IdentityProvider).collect(toList());
			Saml2IdentityProviderMetadata result = new Saml2IdentityProviderMetadata(metadata);
			result.setProviders(providers);
			result.setImplementation(metadata.getImplementation());
			result.setOriginalXML(metadata.getOriginalXML());
			return result;
		}
	}

	private ServiceProviderMetadata generateMetadata(HostedSaml2ServiceProviderConfiguration configuration) {

		String pathPrefix = configuration.getPathPrefix();
		List<Saml2KeyData> keys = configuration.getKeys();
		String aliasPath = getAliasPath(configuration);
		String baseUrl = configuration.getBasePath();
		String entityId =
			hasText(configuration.getEntityId()) ? configuration.getEntityId() : baseUrl;

		return new ServiceProviderMetadata()
			.setEntityId(entityId)
			.setEntityAlias(getEntityAlias(configuration, entityId))
			.setId("M" + UUID.randomUUID().toString())
			.setSigningKey(keys.get(0), RSA_SHA256, SHA256)
			.setProviders(
				asList(
					new org.springframework.security.saml2.model.metadata.ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(configuration.isWantAssertionsSigned())
						.setAuthnRequestsSigned(keys.size() > 0 && configuration.isSignRequests())
						.setAssertionConsumerService(
							asList(
								getEndpoint(
									baseUrl,
									stripSlashes(pathPrefix) + "/SSO/alias/" + stripStartingSlashes(aliasPath),
									Saml2Binding.POST,
									0,
									true
								),
								getEndpoint(
									baseUrl,
									stripSlashes(pathPrefix) + "/SSO/alias/" + stripStartingSlashes(aliasPath),
									REDIRECT,
									1,
									false
								)
							)
						)
						.setNameIds(asList(Saml2NameId.PERSISTENT, Saml2NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							configuration.isSingleLogoutEnabled() ?
								asList(
									getEndpoint(
										baseUrl,
										stripSlashes(pathPrefix) + "/logout/alias/" + stripStartingSlashes(aliasPath),
										REDIRECT,
										0,
										true
									)
								)
								:
								emptyList()
						)
				)
			);
	}

	private String getEntityAlias(HostedSaml2ServiceProviderConfiguration configuration, String entityId) {
		return hasText(configuration.getAlias()) ? configuration.getAlias() :
			isUrl(entityId) ? Saml2StringUtils.getHostFromUrl(entityId) : entityId;
	}

	private Saml2Endpoint getEndpoint(String baseUrl, String path, Saml2Binding binding, int index, boolean isDefault) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
		builder.pathSegment(path);
		return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
	}

	private Saml2Endpoint getEndpoint(String url, Saml2Binding binding, int index, boolean isDefault) {
		return
			new Saml2Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}

	private String getAliasPath(HostedSaml2ProviderConfiguration configuration) {
		return UriUtils.encode(
			Saml2StringUtils.getAliasPath(configuration.getAlias(), configuration.getEntityId()),
			StandardCharsets.ISO_8859_1.name()
		);
	}

	private boolean isUri(String uri) {
		boolean isUri = false;
		try {
			new URI(uri);
			isUri = true;
		} catch (URISyntaxException e) {
		}
		return isUri;
	}

}

