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

package org.springframework.security.saml.provider.service;

import java.util.List;
import java.util.UUID;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.AbstractHostedProviderService;
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
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import org.joda.time.DateTime;

public class HostedServiceProviderService extends AbstractHostedProviderService<
	LocalServiceProviderConfiguration,
	ServiceProviderMetadata,
	IdentityProviderMetadata> implements ServiceProviderService {


	public HostedServiceProviderService(LocalServiceProviderConfiguration configuration,
										ServiceProviderMetadata metadata,
										SamlTransformer transformer,
										SamlValidator validator,
										SamlMetadataCache cache) {
		super(configuration, metadata, transformer, validator, cache);
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
	public IdentityProviderMetadata getRemoteProvider(Saml2Object saml2Object) {
		if (saml2Object instanceof Assertion) {
			return getRemoteProvider((Assertion)saml2Object);
		}
		else if (saml2Object instanceof Response) {
			return getRemoteProvider((Response)saml2Object);
		}
		else if (saml2Object instanceof LogoutRequest) {
			return getRemoteProvider((LogoutRequest)saml2Object);
		}
		else if (saml2Object instanceof LogoutResponse) {
			return getRemoteProvider((LogoutResponse)saml2Object);
		}
		else {
			throw new UnsupportedOperationException("Class:"+saml2Object.getClass().getName()+" not yet implemented");
		}
	}

	@Override
	public AuthenticationRequest authenticationRequest(IdentityProviderMetadata idp) {
		ServiceProviderMetadata sp = getMetadata();
		AuthenticationRequest request = new AuthenticationRequest()
			.setId(UUID.randomUUID().toString())
			.setIssueInstant(new DateTime(getClock().millis()))
			.setForceAuth(Boolean.FALSE)
			.setPassive(Boolean.FALSE)
			.setBinding(Binding.POST)
			.setAssertionConsumerService(getACSFromSp(sp))
			.setIssuer(new Issuer().setValue(sp.getEntityId()))
			.setDestination(idp.getIdentityProvider().getSingleSignOnService().get(0));
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		NameIdPolicy policy;
		if (idp.getDefaultNameId() != null) {
			policy = new NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityAlias(),
				true
			);
		}
		else {
			policy = new NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityAlias(),
				true
			);
		}
		request.setNameIdPolicy(policy);
		return request;
	}

	@Override
	public Endpoint getSingleSignOnEndpoint() {
		List<Endpoint> endpoints = getMetadata().getServiceProvider().getSingleLogoutService();
		return getSingleLogout(endpoints);
	}
}
