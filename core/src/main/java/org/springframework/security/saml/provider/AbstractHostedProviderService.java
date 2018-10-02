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

package org.springframework.security.saml.provider;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlMetadataException;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.config.HostedProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.metadata.SsoProvider;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.validation.ValidationException;
import org.springframework.security.saml.validation.ValidationResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

import static java.lang.String.format;
import static java.util.Collections.emptyList;

public abstract class AbstractHostedProviderService<
	Configuration extends HostedProviderConfiguration,
	LocalMetadata extends Metadata<LocalMetadata>,
	RemoteMetadata extends Metadata<RemoteMetadata>>
	implements HostedProviderService<Configuration, LocalMetadata, RemoteMetadata> {

	private static Log logger = LogFactory.getLog(AbstractHostedProviderService.class);

	private final Configuration configuration;
	private final LocalMetadata metadata;
	private final SamlTransformer transformer;
	private final SamlValidator validator;
	private final SamlMetadataCache cache;
	private Clock clock = Clock.systemUTC();

	public AbstractHostedProviderService(Configuration configuration,
										 LocalMetadata metadata,
										 SamlTransformer transformer,
										 SamlValidator validator,
										 SamlMetadataCache cache) {
		this.configuration = configuration;
		this.metadata = metadata;
		this.transformer = transformer;
		this.validator = validator;
		this.cache = cache;
	}

	public Clock getClock() {
		return clock;
	}

	public AbstractHostedProviderService<Configuration, LocalMetadata, RemoteMetadata> setClock(Clock clock) {
		this.clock = clock;
		return this;
	}

	public SamlMetadataCache getCache() {
		return cache;
	}

	protected RemoteMetadata getRemoteProvider(Issuer issuer) {
		if (issuer == null) {
			return null;
		}
		else {
			return getRemoteProvider(issuer.getValue());
		}
	}

	protected RemoteMetadata throwIfNull(RemoteMetadata metadata, String key, String value) {
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
	public Configuration getConfiguration() {
		return configuration;
	}

	@Override
	public LocalMetadata getMetadata() {
		return metadata;
	}

	@Override
	public List<RemoteMetadata> getRemoteProviders() {
		List<RemoteMetadata> result = new LinkedList<>();
		List<ExternalProviderConfiguration> providers = getConfiguration().getProviders();
		for (ExternalProviderConfiguration c : providers) {
			try {
				RemoteMetadata m = getRemoteProvider(c);
				if (m != null) {
					m.setEntityAlias(c.getAlias());
					result.add(m);
				}
			} catch (SamlException x) {
				logger.debug("Unable to resolve identity provider metadata.", x);
			}
		}
		return result;
	}

	@Override
	public LogoutRequest logoutRequest(RemoteMetadata recipient, NameIdPrincipal principal) {
		LocalMetadata local = this.getMetadata();

		List<SsoProvider> ssoProviders = recipient.getSsoProviders();
		LogoutRequest result = new LogoutRequest()
			.setId(UUID.randomUUID().toString())
			.setDestination(
				getPreferredEndpoint(
					ssoProviders.get(0).getSingleLogoutService(),
					null,
					-1
				)
			)
			.setIssuer(new Issuer().setValue(local.getEntityId()))
			.setIssueInstant(DateTime.now())
			.setNameId(principal)
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());

		return result;
	}

	@Override
	public LogoutResponse logoutResponse(LogoutRequest request, RemoteMetadata recipient) {
		List<SsoProvider> ssoProviders = recipient.getSsoProviders();
		Endpoint destination = getPreferredEndpoint(
			ssoProviders.get(0).getSingleLogoutService(),
			null,
			-1
		);
		return new LogoutResponse()
			.setId(UUID.randomUUID().toString())
			.setInResponseTo(request != null ? request.getId() : null)
			.setDestination(destination != null ? destination.getLocation() : null)
			.setStatus(new Status().setCode(StatusCode.SUCCESS))
			.setIssuer(new Issuer().setValue(getMetadata().getEntityId()))
			.setSigningKey(getMetadata().getSigningKey(), getMetadata().getAlgorithm(), getMetadata().getDigest())
			.setIssueInstant(new DateTime())
			.setVersion("2.0");
	}

	@Override
	public abstract RemoteMetadata getRemoteProvider(Saml2Object saml2Object);

	@Override
	public RemoteMetadata getRemoteProvider(String entityId) {
		for (RemoteMetadata m : getRemoteProviders()) {
			while (m != null) {
				if (entityId.equals(m.getEntityId())) {
					return m;
				}
				m = m.hasNext() ? m.getNext() : null;
			}
		}
		return
			throwIfNull(
				null,
				"remote provider entityId",
				entityId
			);
	}

	@Override
	public RemoteMetadata getRemoteProvider(ExternalProviderConfiguration c) {
		String metadata = c.getMetadata();
		return resolve(metadata, c.isSkipSslValidation());
	}

	@Override
	public ValidationResult validate(Saml2Object saml2Object) {
		RemoteMetadata remote = getRemoteProvider(saml2Object);
		List<SimpleKey> verificationKeys = getVerificationKeys(remote);
		try {
			if (verificationKeys != null && !verificationKeys.isEmpty()) {
				getValidator().validateSignature(saml2Object, verificationKeys);
			}
		} catch (SignatureException x) {
			return new ValidationResult(saml2Object).addError(
				new ValidationResult.ValidationError(x.getMessage())
			);
		}
		try {
			getValidator().validate(saml2Object, this);
		} catch (ValidationException e) {
			return e.getErrors();
		}
		return new ValidationResult(saml2Object);
	}

	private List<SimpleKey> getVerificationKeys(RemoteMetadata remote) {
		List<SimpleKey> verificationKeys = emptyList();
		if (remote instanceof ServiceProviderMetadata) {
			verificationKeys = ((ServiceProviderMetadata) remote).getServiceProvider().getKeys();
		}
		else if (remote instanceof IdentityProviderMetadata) {
			verificationKeys = ((IdentityProviderMetadata) remote).getIdentityProvider().getKeys();
		}
		return verificationKeys;
	}

	public SamlValidator getValidator() {
		return validator;
	}

	@Override
	public <T extends Saml2Object> T fromXml(String xml, boolean encoded, boolean deflated, Class<T> type) {
		List<SimpleKey> decryptionKeys = getConfiguration().getKeys();
		if (encoded) {
			xml = getTransformer().samlDecode(xml, deflated);
		}
		Saml2Object result = type.cast(getTransformer().fromXml(xml, null, decryptionKeys));
		//in order to add signatures, we need the verification keys from the remote provider
		RemoteMetadata remote = getRemoteProvider(result);
		List verificationKeys = remote.getSsoProviders().get(0).getKeys();
		//perform transformation with verification keys
		return type.cast(getTransformer().fromXml(xml, verificationKeys, decryptionKeys));
	}

	@Override
	public String toXml(Saml2Object saml2Object) {
		return getTransformer().toXml(saml2Object);
	}

	@Override
	public String toEncodedXml(Saml2Object saml2Object, boolean deflate) {
		String xml = toXml(saml2Object);
		return toEncodedXml(xml, deflate);
	}

	@Override
	public String toEncodedXml(String xml, boolean deflate) {
		return getTransformer().samlEncode(xml, deflate);
	}

	@Override
	public Endpoint getPreferredEndpoint(List<Endpoint> endpoints,
										 Binding preferredBinding,
										 int preferredIndex) {
		if (endpoints == null || endpoints.isEmpty()) {
			return null;
		}
		List<Endpoint> eps = endpoints;
		Endpoint result = null;
		//find the preferred binding
		if (preferredBinding != null) {
			for (Endpoint e : eps) {
				if (preferredBinding == e.getBinding()) {
					result = e;
					break;
				}
			}
		}
		//find the configured index
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.getIndex() == preferredIndex) {
					result = e;
					break;
				}
			}
		}
		//find the default endpoint
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.isDefault()) {
					result = e;
					break;
				}
			}
		}
		//fallback to the very first available endpoint
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

	public SamlTransformer getTransformer() {
		return transformer;
	}

	private RemoteMetadata resolve(String metadata, boolean skipSslValidation) {
		RemoteMetadata result;
		if (isUri(metadata)) {
			try {
				byte[] data = cache.getMetadata(metadata, skipSslValidation);
				result = transformMetadata(new String(data, StandardCharsets.UTF_8));
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
			result = transformMetadata(metadata);
		}
		return throwIfNull(
			result,
			"metadata",
			metadata
		);
	}

	protected abstract RemoteMetadata transformMetadata(String data);

	private boolean isUri(String uri) {
		boolean isUri = false;
		try {
			new URI(uri);
			isUri = true;
		} catch (URISyntaxException e) {
		}
		return isUri;
	}

	protected RemoteMetadata getRemoteProvider(LogoutResponse response) {
		String issuer = response.getIssuer() != null ?
			response.getIssuer().getValue() :
			null;
		return getRemoteProvider(issuer);
	}

	protected RemoteMetadata getRemoteProvider(LogoutRequest request) {
		String issuer = request.getIssuer() != null ?
			request.getIssuer().getValue() :
			null;
		return getRemoteProvider(issuer);
	}
}
