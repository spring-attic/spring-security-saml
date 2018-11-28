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

package org.springframework.security.saml.serviceprovider.implementation;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMetadataException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.registration.HostedProviderConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.util.RestOperationsUtils;
import org.springframework.security.saml.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA256;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA256;
import static org.springframework.security.saml.util.StringUtils.isUrl;
import static org.springframework.security.saml.util.StringUtils.stripSlashes;
import static org.springframework.security.saml.util.StringUtils.stripStartingSlashes;
import static org.springframework.util.StringUtils.hasText;

public class ServiceProviderMetadataResolver {
	private static Log logger = LogFactory.getLog(ServiceProviderMetadataResolver.class);

	private final SamlTransformer samlTransformer;

	private SamlMetadataCache cache = new DefaultMetadataCache(
		Clock.systemUTC(),
		new RestOperationsUtils(4000, 4000).get(false),
		new RestOperationsUtils(4000, 4000).get(true)
	);

	public ServiceProviderMetadataResolver(SamlTransformer samlTransformer) {
		this.samlTransformer = samlTransformer;
	}

	public ServiceProviderMetadataResolver setCache(SamlMetadataCache cache) {
		this.cache = cache;
		return this;
	}

	public ServiceProviderMetadata resolveHostedServiceProvider(HostedServiceProviderConfiguration configuration) {
		return generateMetadata(configuration);
	}

	public Map<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> resolveConfiguredProviders(
		HostedServiceProviderConfiguration configuration
	) {
		return getProviders(configuration);
	}

	private Map<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> getProviders(
		HostedServiceProviderConfiguration configuration) {
		Map<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> result = new HashMap<>();
		List<ExternalIdentityProviderConfiguration> providers = configuration.getProviders();
		for (ExternalIdentityProviderConfiguration idpConfig : providers) {
			IdentityProviderMetadata idp = getIdentityProviderMetadata(idpConfig);
			if (idp != null) {
				result.put(idpConfig, idp);
			}
		}
		return result;
	}

	private IdentityProviderMetadata getIdentityProviderMetadata(ExternalIdentityProviderConfiguration idp) {
		try {
			byte[] data = idp.getMetadata().getBytes(StandardCharsets.UTF_8);
			if (isUri(idp.getMetadata())) {
				data = cache.getMetadata(idp.getMetadata(), idp.isSkipSslValidation());
			}
			IdentityProviderMetadata metadata = (IdentityProviderMetadata) samlTransformer.fromXml(data, null, null);
			metadata.setEntityAlias(idp.getAlias());
			return metadata;
		} catch (SamlMetadataException e) {
			logger.debug("Unable to resolve remote metadata:" + e.getMessage());
			return null;
		}
	}

	private ServiceProviderMetadata generateMetadata(HostedServiceProviderConfiguration configuration) {

		String prefix = configuration.getPrefix();
		List<KeyData> keys = configuration.getKeys();
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
					new org.springframework.security.saml.saml2.metadata.ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(true)
						.setAuthnRequestsSigned(keys.size() > 0 && configuration.isSignRequests())
						.setAssertionConsumerService(
							asList(
								getEndpoint(
									baseUrl,
									stripSlashes(prefix) + "/SSO/alias/" + stripStartingSlashes(aliasPath),
									Binding.POST,
									0,
									true
								),
								getEndpoint(
									baseUrl,
									stripSlashes(prefix) + "/SSO/alias/" + stripStartingSlashes(aliasPath),
									REDIRECT,
									1,
									false
								)
							)
						)
						.setNameIds(asList(NameId.PERSISTENT, NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(
									baseUrl,
									stripSlashes(prefix) + "/logout/alias/" + stripStartingSlashes(aliasPath),
									REDIRECT,
									0,
									true
								)
							)
						)
				)
			);
	}

	private String getEntityAlias(HostedServiceProviderConfiguration configuration, String entityId) {
		return hasText(configuration.getAlias()) ? configuration.getAlias() :
			isUrl(entityId) ? StringUtils.getHostFromUrl(entityId) : entityId;
	}

	private Endpoint getEndpoint(String baseUrl, String path, Binding binding, int index, boolean isDefault) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
		builder.pathSegment(path);
		return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
	}

	private Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault) {
		return
			new Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}

	private String getAliasPath(HostedProviderConfiguration configuration) {
		try {
			return hasText(configuration.getAlias()) ?
				UriUtils.encode(configuration.getAlias(), StandardCharsets.ISO_8859_1.name()) :
				UriUtils.encode(configuration.getEntityId(), StandardCharsets.ISO_8859_1.name());
		} catch (UnsupportedEncodingException e) {
			throw new SamlException(e);
		}
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

