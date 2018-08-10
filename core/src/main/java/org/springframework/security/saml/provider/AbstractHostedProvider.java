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
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
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
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;

public abstract class AbstractHostedProvider<
	Configuration extends LocalProviderConfiguration,
	LocalMetadata extends Metadata<LocalMetadata>,
	RemoteMetadata extends Metadata<RemoteMetadata>>
	implements HostedProvider<Configuration, LocalMetadata, RemoteMetadata> {

	private static Log logger = LogFactory.getLog(AbstractHostedProvider.class);

	private final Configuration configuration;
	private final LocalMetadata metadata;
	private final SamlTransformer transformer;
	private final SamlValidator validator;
	private final SamlMetadataCache cache;
	private Clock clock = Clock.systemUTC();

	public AbstractHostedProvider(Configuration configuration,
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

	@Override
	public Configuration getConfiguration() {
		return configuration;
	}

	@Override
	public LocalMetadata getMetadata() {
		return metadata;
	}

	@Override
	public LogoutRequest logoutRequest(RemoteMetadata recipient, NameIdPrincipal principal) {
		LocalMetadata local = this.getMetadata();

		List<SsoProvider> ssoProviders = recipient.getSsoProviders();
		LogoutRequest result = new LogoutRequest()
			.setId(UUID.randomUUID().toString())
			.setDestination(getSingleLogout(ssoProviders.get(0).getSingleLogoutService()))
			.setIssuer(new Issuer().setValue(local.getEntityId()))
			.setIssueInstant(DateTime.now())
			.setNameId(principal)
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());

		return result;
	}

	@Override
	public LogoutResponse logoutResponse(LogoutRequest request, RemoteMetadata recipient) {
		List<SsoProvider> ssoProviders = recipient.getSsoProviders();
		Endpoint destination = getSingleLogout(ssoProviders.get(0).getSingleLogoutService());
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
	public List<RemoteMetadata> getRemoteProviders() {
		List<RemoteMetadata> result = new LinkedList<>();
		List<ExternalProviderConfiguration> providers = getConfiguration().getProviders();
		for (ExternalProviderConfiguration c : providers) {
			String metadata = c.getMetadata();
			try {
				RemoteMetadata m = resolve(metadata, c.isSkipSslValidation());
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

	protected Endpoint getACSFromSp(ServiceProviderMetadata sp) {
		Endpoint endpoint = sp.getServiceProvider().getAssertionConsumerService().get(0);
		for (Endpoint e : sp.getServiceProvider().getAssertionConsumerService()) {
			if (e.isDefault()) {
				endpoint = e;
			}
		}
		return endpoint;
	}

	private RemoteMetadata resolve(String metadata, boolean skipSslValidation) {
		RemoteMetadata result;
		if (isUri(metadata)) {
			try {
				byte[] data = cache.getMetadata(metadata, skipSslValidation);
				result = (RemoteMetadata) transformer.fromXml(data, null, null);
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
			result = (RemoteMetadata) transformer.fromXml(metadata, null, null);
		}
		return throwIfNull(
			result,
			"metadata",
			metadata
		);
	}

	@Override
	public ValidationResult validate(Saml2Object saml2Object) {
		RemoteMetadata remote = getRemoteProvider(saml2Object);
		List<SimpleKey> verificationKeys = getVerificationKeys(remote);
		try {
			getValidator().validateSignature(saml2Object, verificationKeys);
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
			verificationKeys = ((ServiceProviderMetadata)remote).getServiceProvider().getKeys();
		}
		else if (remote instanceof IdentityProviderMetadata) {
			verificationKeys = ((IdentityProviderMetadata)remote).getIdentityProvider().getKeys();
		}
		return verificationKeys;
	}

	@Override
	public <T extends Saml2Object> T fromXml(String xml, boolean encoded, boolean deflated, Class<T> type) {
		List<SimpleKey> decryptionKeys = getConfiguration().getKeys().toList();
		if (encoded) {
			xml = getTransformer().samlDecode(xml, deflated);
		}
		return type.cast(getTransformer().fromXml(xml, null, decryptionKeys));
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

	public SamlTransformer getTransformer() {
		return transformer;
	}

	public SamlValidator getValidator() {
		return validator;
	}

	public Clock getClock() {
		return clock;
	}

	public SamlMetadataCache getCache() {
		return cache;
	}

	public AbstractHostedProvider<Configuration, LocalMetadata, RemoteMetadata> setClock(Clock clock) {
		this.clock = clock;
		return this;
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

	protected Endpoint getSingleLogout(List<Endpoint> logoutService) {
		if (logoutService == null || logoutService.isEmpty()) {
			return null;
		}
		List<Endpoint> eps = logoutService;
		Endpoint result = null;
		for (Endpoint e : eps) {
			if (e.isDefault()) {
				result = e;
				break;
			} else if (REDIRECT.equals(e.getBinding())) {
				result = e;
				break;
			}
		}
		if (result == null ) {
			result = eps.get(0);
		}
		return result;
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
