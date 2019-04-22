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

package org.springframework.security.saml.provider.service;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.AbstractHostedProviderService;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.metadata.SsoProvider;

import org.joda.time.DateTime;

import static java.util.Optional.ofNullable;

public class HostedServiceProviderService extends AbstractHostedProviderService<
	LocalServiceProviderConfiguration,
	ServiceProviderMetadata,
	IdentityProviderMetadata> implements ServiceProviderService {

	private AuthenticationRequestEnhancer authnRequestEnhancer;

	public HostedServiceProviderService(LocalServiceProviderConfiguration configuration,
										ServiceProviderMetadata metadata,
										SamlTransformer transformer,
										SamlValidator validator,
										SamlMetadataCache cache,
										AuthenticationRequestEnhancer authnRequestEnhancer) {
		super(configuration, metadata, transformer, validator, cache);
		this.authnRequestEnhancer = ofNullable(authnRequestEnhancer)
			.orElseGet(() -> authenticationRequest -> authenticationRequest);
	}

	@Override
	public IdentityProviderMetadata getRemoteProvider(ExternalProviderConfiguration c) {
		IdentityProviderMetadata metadata = super.getRemoteProvider(c);
		if (metadata != null && c instanceof ExternalIdentityProviderConfiguration) {
			ExternalIdentityProviderConfiguration ec = (ExternalIdentityProviderConfiguration) c;
			if (ec.getNameId() != null) {
				metadata.setDefaultNameId(ec.getNameId());
			}
		}
		return metadata;
	}

	@Override
	protected IdentityProviderMetadata transformMetadata(String data) {
		Metadata metadata = (Metadata) getTransformer().fromXml(data, null, null);
		IdentityProviderMetadata result;
		if (metadata instanceof IdentityProviderMetadata) {
			result = (IdentityProviderMetadata) metadata;
		}
		else {
			List<SsoProvider> providers = metadata.getSsoProviders();
			providers = providers.stream().filter(p -> p instanceof IdentityProvider).collect(Collectors.toList());
			result = new IdentityProviderMetadata(metadata);
			result.setProviders(providers);
		}
		return result;
	}

	@Override
	public IdentityProviderMetadata getRemoteProvider(Saml2Object saml2Object) {
		if (saml2Object instanceof Assertion) {
			return getRemoteProvider((Assertion) saml2Object);
		}
		else if (saml2Object instanceof Response) {
			return getRemoteProvider((Response) saml2Object);
		}
		else if (saml2Object instanceof LogoutRequest) {
			return getRemoteProvider((LogoutRequest) saml2Object);
		}
		else if (saml2Object instanceof LogoutResponse) {
			return getRemoteProvider((LogoutResponse) saml2Object);
		}
		else {
			throw new UnsupportedOperationException("Class:" +
				saml2Object.getClass().getName() +
				" not yet implemented");
		}
	}

	public IdentityProviderMetadata getRemoteProvider(Assertion assertion) {
		String issuer = assertion.getIssuer() != null ?
			assertion.getIssuer().getValue() :
			null;
		return getRemoteProvider(issuer);
	}

	public IdentityProviderMetadata getRemoteProvider(Response response) {
		String issuer = response.getIssuer() != null ?
			response.getIssuer().getValue() :
			null;
		return getRemoteProvider(issuer);
	}

	@Override
	public AuthenticationRequest authenticationRequest(IdentityProviderMetadata idp) {
		ExternalIdentityProviderConfiguration configuration = getIdentityProviderConfigurationForMetadata(idp);
		final URI authnBinding = configuration.getAuthenticationRequestBinding();
		Binding preferredBinding = authnBinding == null ?
			Binding.REDIRECT :
			Binding.fromUrn(authnBinding);
		Endpoint endpoint = getPreferredEndpoint(
			idp.getIdentityProvider().getSingleSignOnService(),
			preferredBinding,
			0
		);
		ServiceProviderMetadata sp = getMetadata();
		AuthenticationRequest request = new AuthenticationRequest()
			// Some service providers will not accept first character if 0..9
			// Azure AD IdP for example.
			.setId("ARQ" + UUID.randomUUID().toString().substring(1))
			.setIssueInstant(new DateTime(getClock().millis()))
			.setForceAuth(Boolean.FALSE)
			.setPassive(Boolean.FALSE)
			.setBinding(endpoint.getBinding())
			.setAssertionConsumerService(
				getPreferredEndpoint(
					sp.getServiceProvider().getAssertionConsumerService(),
					null,
					-1
				)
			)
			.setIssuer(new Issuer().setValue(sp.getEntityId()))
			.setDestination(endpoint);
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		if (idp.getDefaultNameId() != null) {
			request.setNameIdPolicy(new NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityAlias(),
				true
			));
		}
		else if (idp.getIdentityProvider().getNameIds().size() > 0) {
			request.setNameIdPolicy(new NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityAlias(),
				true
			));
		}
		return authnRequestEnhancer.enhance(request);
	}

	private ExternalIdentityProviderConfiguration getIdentityProviderConfigurationForMetadata(
		IdentityProviderMetadata idp) {
		return getConfiguration()
			.getProviders()
			.stream()
			.filter(i -> i.getAlias().equals(idp.getEntityAlias()))
			.findFirst()
			.orElseThrow(() -> new SamlProviderNotFoundException("alias:" + idp.getEntityAlias()));
	}
}
