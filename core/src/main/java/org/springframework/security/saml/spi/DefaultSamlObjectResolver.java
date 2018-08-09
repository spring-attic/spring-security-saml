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
package org.springframework.security.saml.spi;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.SamlException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlMetadataException;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.deprecated.SamlDefaults;
import org.springframework.security.saml.util.Network;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static org.springframework.util.StringUtils.hasText;

public class DefaultSamlObjectResolver implements SamlObjectResolver {

	private static final Log logger = LogFactory.getLog(DefaultSamlObjectResolver.class);

	private SamlServerConfiguration configuration;
	private SamlDefaults samlDefaults;
	private SamlTransformer transformer;
	private Network network;
	private SamlMetadataCache cache;

	@Autowired
	public DefaultSamlObjectResolver setTransformer(SamlTransformer transformer) {
		this.transformer = transformer;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setSamlServerConfiguration(SamlServerConfiguration configuration) {
		this.configuration = configuration;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setSamlDefaults(SamlDefaults samlDefaults) {
		this.samlDefaults = samlDefaults;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setNetwork(Network network) {
		this.network = network;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setMetadataCache(SamlMetadataCache cache) {
		this.cache = cache;
		return this;
	}

	@Override
	public ServiceProviderMetadata getLocalServiceProvider(String baseUrl) {
		LocalServiceProviderConfiguration sp = configuration.getServiceProvider();
		if (sp == null) {
			throw new SamlProviderNotFoundException("No local service provider configured.");
		}
		ServiceProviderMetadata metadata = samlDefaults.serviceProviderMetadata(baseUrl, sp);
		if (!sp.isSingleLogoutEnabled()) {
			metadata.getServiceProvider().setSingleLogoutService(Collections.emptyList());
		}
		if (hasText(sp.getEntityId())) {
			metadata.setEntityId(sp.getEntityId());
		}
		if (hasText(sp.getAlias())) {
			metadata.setEntityAlias(sp.getAlias());
		}
		metadata.getServiceProvider().setWantAssertionsSigned(sp.isWantAssertionsSigned());
		metadata.getServiceProvider().setAuthnRequestsSigned(sp.isSignRequests());
		return metadata;
	}

	@Override
	public IdentityProviderMetadata getLocalIdentityProvider(String baseUrl) {
		LocalIdentityProviderConfiguration idp = configuration.getIdentityProvider();
		if (idp == null) {
			throw new SamlProviderNotFoundException("No local identity provider configured.");
		}
		IdentityProviderMetadata metadata = samlDefaults.identityProviderMetadata(baseUrl, idp);
		if (!idp.isSingleLogoutEnabled()) {
			metadata.getIdentityProvider().setSingleLogoutService(Collections.emptyList());
		}
		if (hasText(idp.getEntityId())) {
			metadata.setEntityId(idp.getEntityId());
		}
		if (hasText(idp.getAlias())) {
			metadata.setEntityAlias(idp.getAlias());
		}

		metadata.getIdentityProvider().setWantAuthnRequestsSigned(idp.isWantRequestsSigned());
		return metadata;
	}

	protected <T extends Metadata> T throwIfNull(T metadata, String key, String value) {
		if (metadata == null) {
			String message = "Provider for key '%s' with value '%s' not found.";
			throw new SamlProviderNotFoundException(
				String.format(message, key, value)
			);
		}
		else {
			return metadata;
		}
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(Assertion assertion) {
		String issuer = assertion.getIssuer() != null ?
			assertion.getIssuer().getValue() :
			null;
		return
			throwIfNull(
				resolveIdentityProvider(issuer),
				"assertion issuer",
				issuer
			);
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(Response response) {
		String issuer = response.getIssuer() != null ?
			response.getIssuer().getValue() :
			null;
		return
			throwIfNull(
				resolveIdentityProvider(issuer),
				"response issuer",
				issuer
			);
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(String entityId) {
		LocalServiceProviderConfiguration idp = configuration.getServiceProvider();
		for (ExternalProviderConfiguration c : idp.getProviders()) {
			String metadata = c.getMetadata();
			try {
				Metadata m = resolve(metadata, c.isSkipSslValidation());
				while (m != null) {
					if (m instanceof IdentityProviderMetadata && entityId.equals(m.getEntityId())) {
						m.setEntityAlias(c.getAlias());
						return (IdentityProviderMetadata) m;
					}
					m = m.hasNext() ? (IdentityProviderMetadata) m.getNext() : null;
				}
			} catch (SamlException x) {
				logger.debug("Unable to resolve identity provider metadata.", x);
			}

		}
		return
			throwIfNull(
				null,
				"identity provider entityId",
				entityId
			);
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(LogoutRequest logoutRequest) {
		String issuer = logoutRequest.getIssuer() != null ?
			logoutRequest.getIssuer().getValue() :
			null;
		return
			throwIfNull(
				resolveIdentityProvider(issuer),
				"logout request issuer",
				issuer
			);

	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(ExternalProviderConfiguration idp) {
		if (idp == null) {
			throw new SamlProviderNotFoundException("Identity provider configuration must not be null");
		}
		return
			throwIfNull(
				(IdentityProviderMetadata) resolve(idp.getMetadata(), idp.isSkipSslValidation()),
				"identity provider configuration metadata",
				idp.getMetadata()
			);
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(String entityId) {
		LocalIdentityProviderConfiguration idp = configuration.getIdentityProvider();
		for (ExternalProviderConfiguration c : idp.getProviders()) {
			String metadata = c.getMetadata();
			try {
				Metadata m = resolve(metadata, c.isSkipSslValidation());
				while (m != null) {
					if (m instanceof ServiceProviderMetadata && entityId.equals(m.getEntityId())) {
						m.setEntityAlias(c.getAlias());
						return (ServiceProviderMetadata) m;
					}
					m = m.hasNext() ? (ServiceProviderMetadata)m.getNext() : null;
				}
			} catch (SamlException x) {
				logger.debug("Unable to resolve service provider metadata.", x);
			}
		}
		return
			throwIfNull(
				null,
				"service provider entityId",
				entityId
			);
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(AuthenticationRequest request) {
		String issuer = request.getIssuer() != null ?
			request.getIssuer().getValue() :
			null;
		ServiceProviderMetadata result = resolveServiceProvider(issuer);
		return
			throwIfNull(
				result,
				"authentication request issuer",
				issuer
			);
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(ExternalProviderConfiguration sp) {
		if (sp == null) {
			throw new SamlProviderNotFoundException("Service Provider configuration must not be null");
		}
		return
			throwIfNull(
				(ServiceProviderMetadata) resolve(sp.getMetadata(), sp.isSkipSslValidation()),
				"service provider configuration metadata",
				sp.getMetadata()
			);


	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(LogoutRequest logoutRequest) {
		String issuer = logoutRequest.getIssuer() != null ?
			logoutRequest.getIssuer().getValue() :
			null;
		ServiceProviderMetadata result = resolveServiceProvider(issuer);
		return
			throwIfNull(
				result,
				"logout request issuer",
				issuer
			);
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(Assertion localAssertion) {
		if (localAssertion == null || localAssertion.getSubject() == null) {
			throw new SamlProviderNotFoundException("Assertion must not be null");
		}

		Subject subject = localAssertion.getSubject();
		NameIdPrincipal principal = subject.getPrincipal();

		String spNameQualifier = principal != null ?
			principal.getSpNameQualifier() :
			null;

		return throwIfNull(
			resolveServiceProvider(spNameQualifier),
			"assertion sp name qualifier",
			spNameQualifier
		);

	}

	protected Metadata resolve(String metadata, boolean skipSslValidation) {
		Metadata result;
		if (isUri(metadata)) {
			try {
				byte[] data = cache.getMetadata(metadata, skipSslValidation);
				result = (Metadata) transformer.fromXml(data, null, null);
			} catch (SamlException x) {
				throw x;
			} catch (Exception x) {
				String message = format("Unable to fetch metadata from: %s with message: %s", metadata, x.getMessage());
				if (logger.isDebugEnabled()) {
					logger.debug(message, x);
				}
				else {
					logger.info(message);
				}
				throw new SamlMetadataException("Unable to successfully get metadata from:" + metadata, x);
			}
		}
		else {
			result = (Metadata) transformer.fromXml(metadata, null, null);
		}
		return throwIfNull(
			result,
			"metadata",
			metadata
		);
	}

	protected boolean isUri(String uri) {
		boolean isUri = false;
		try {
			new URI(uri);
			isUri = true;
		} catch (URISyntaxException e) {
		}
		return isUri;
	}

	protected List<SimpleKey> getSimpleKeys(LocalProviderConfiguration sp) {
		List<SimpleKey> keys = new LinkedList<>();
		keys.add(sp.getKeys().getActive());
		keys.addAll(sp.getKeys().getStandBy());
		return keys;
	}
}
