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

package org.springframework.security.saml.provider.identity;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

public class IdpAuthenticationRequestFilter extends IdpInitiatedLoginFilter {

	public IdpAuthenticationRequestFilter(SamlProviderProvisioning<IdentityProviderService> provisioning,
										  SamlMessageStore<Assertion, HttpServletRequest> assertionStore) {
		this(
			provisioning,
			assertionStore,
			new SamlRequestMatcher(provisioning, "SSO")
		);
	}

	public IdpAuthenticationRequestFilter(SamlProviderProvisioning<IdentityProviderService> provisioning,
										  SamlMessageStore<Assertion, HttpServletRequest> assertionStore,
										  SamlRequestMatcher requestMatcher) {
		super(provisioning, assertionStore, requestMatcher);
	}

	@Override
	protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
		IdentityProviderService provider = getProvisioning().getHostedProvider();
		AuthenticationRequest authn = getAuthenticationRequest(request);
		provider.validate(authn);
		return provider.getRemoteProvider(authn);
	}

	@Override
	protected AuthenticationRequest getAuthenticationRequest(HttpServletRequest request) {
		IdentityProviderService provider = getProvisioning().getHostedProvider();
		String param = request.getParameter("SAMLRequest");
		return
			provider.fromXml(
				param,
				true,
				HttpMethod.GET.name().equalsIgnoreCase(request.getMethod()),
				AuthenticationRequest.class
			);
	}
}
