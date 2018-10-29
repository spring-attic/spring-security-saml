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

package sample.proof_of_concept.support_saved_for_later;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.registration.HostedProviderConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.key.SimpleKey;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saved_for_later.DefaultMetadataCache;
import org.springframework.security.saml.saved_for_later.SamlMetadataCache;
import org.springframework.security.saml.saved_for_later.SamlMetadataException;
import org.springframework.security.saml.util.RestOperationsUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA256;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA256;
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

	public ServiceProviderMetadata resolveHostedServiceProvider(HttpServletRequest request,
																HostedServiceProviderConfiguration configuration) {
		return generateMetadata(request, configuration);
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
			return (IdentityProviderMetadata) samlTransformer.fromXml(data, null, null);
		} catch (SamlMetadataException e) {
			logger.debug("Unable to resolve remote metadata:" + e.getMessage());
			return null;
		}
	}

	private ServiceProviderMetadata generateMetadata(HttpServletRequest request,
													 HostedServiceProviderConfiguration configuration) {

		String baseUrl = hasText(configuration.getBasePath()) ?
			configuration.getBasePath() :
			getBasePath(request, false);

		String prefix = configuration.getPrefix();
		List<SimpleKey> keys = configuration.getKeys();
		String aliasPath = getAliasPath(configuration);
		String entityId = hasText(configuration.getEntityId()) ? configuration.getEntityId() : baseUrl;

		return new ServiceProviderMetadata()
			.setEntityId(entityId)
			.setId("M" + UUID.randomUUID().toString())
			.setSigningKey(keys.get(0), RSA_SHA256, SHA256)
			.setProviders(
				asList(
					new org.springframework.security.saml.saml2.metadata.ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(true)
						.setAuthnRequestsSigned(keys.size() > 0)
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

	private String getBasePath(HttpServletRequest request, boolean includeStandardPorts) {
		boolean includePort = true;
		if (443 == request.getServerPort() && "https".equals(request.getScheme())) {
			includePort = includeStandardPorts;
		}
		else if (80 == request.getServerPort() && "http".equals(request.getScheme())) {
			includePort = includeStandardPorts;
		}
		return request.getScheme() +
			"://" +
			request.getServerName() +
			(includePort ? (":" + request.getServerPort()) : "") +
			request.getContextPath();
	}

	private String getAliasPath(HostedProviderConfiguration configuration) {
		return hasText(configuration.getAlias()) ?
			UriUtils.encode(configuration.getAlias(), StandardCharsets.ISO_8859_1.name()) :
			UriUtils.encode(configuration.getEntityId(), StandardCharsets.ISO_8859_1.name());
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

