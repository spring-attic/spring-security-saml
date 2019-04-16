/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml2.serviceprovider.servlet.authentication;

import java.time.Clock;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.Saml2ProviderNotFoundException;
import org.springframework.security.saml2.configuration.ExternalSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPolicy;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2BindingType;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.serviceprovider.servlet.util.Saml2ServiceProviderMethods;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import org.joda.time.DateTime;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class DefaultSaml2AuthenticationRequestResolver
	implements Saml2AuthenticationRequestResolver {

	private final Saml2ServiceProviderMethods serviceProviderMethods;
	private Clock clock = Clock.systemUTC();

	public DefaultSaml2AuthenticationRequestResolver(Saml2ServiceProviderMethods serviceProviderMethods) {
		this.serviceProviderMethods = serviceProviderMethods;
	}

	@Override
	public Saml2AuthenticationRequest resolve(HttpServletRequest request, HttpServletResponse response) {
		HostedSaml2ServiceProvider provider = serviceProviderMethods.getProvider(request);
		Assert.notNull(provider, "Each request must resolve into a hosted SAML provider");
		Map.Entry<ExternalSaml2IdentityProviderConfiguration, Saml2IdentityProviderMetadata> entity =
			getIdentityProvider(request, provider);
		ExternalSaml2IdentityProviderConfiguration idpConfig = entity.getKey();
		Saml2IdentityProviderMetadata idp = entity.getValue();
		Saml2ServiceProviderMetadata localSp = provider.getMetadata();
		final Saml2BindingType preferredSSOBinding =
			ofNullable(idpConfig.getAuthenticationRequestBinding())
				.orElse(Saml2Binding.REDIRECT)
				.getType();
		return getAuthenticationRequest(
			localSp,
			idp,
			idpConfig.getNameId(),
			idpConfig.getAssertionConsumerServiceIndex(),
			preferredSSOBinding
		);
	}

	/*
	 * UAA would want to override this as the entities are referred to by alias rather
	 * than ID
	 */
	protected Map.Entry<ExternalSaml2IdentityProviderConfiguration, Saml2IdentityProviderMetadata> getIdentityProvider(
		HttpServletRequest request,
		HostedSaml2ServiceProvider sp
	) {
		Map.Entry<ExternalSaml2IdentityProviderConfiguration, Saml2IdentityProviderMetadata> result = null;
		String idpAlias = getIdpAlias(request);
		if (hasText(idpAlias)) {
			result = sp.getRemoteProviders().entrySet().stream()
				.filter(p -> idpAlias.equals(p.getKey().getAlias()))
				.findFirst()
				.orElse(null);
		}
		else if (sp.getRemoteProviders().size() == 1) { //we only have one, consider it the default
			result = sp.getRemoteProviders()
				.entrySet()
				.stream()
				.findFirst()
				.orElse(null);
		}
		if (result == null) {
			throw new Saml2ProviderNotFoundException("Unable to identify a configured identity provider.");
		}
		return result;
	}

	protected Saml2AuthenticationRequest getAuthenticationRequest(Saml2ServiceProviderMetadata sp,
																  Saml2IdentityProviderMetadata idp,
																  Saml2NameId requestedNameId,
																  int preferredACSEndpointIndex,
																  Saml2BindingType preferredSSOBinding) {
		Saml2Endpoint endpoint = serviceProviderMethods.getPreferredEndpoint(
			idp.getIdentityProvider().getSingleSignOnService(),
			preferredSSOBinding,
			-1
		);
		Saml2AuthenticationRequest request = new Saml2AuthenticationRequest()
			// Some service providers will not accept first character if 0..9
			// Azure AD IdP for example.
			.setId("ARQ" + UUID.randomUUID().toString().substring(1))
			.setIssueInstant(new DateTime(clock.millis()))
			.setForceAuth(Boolean.FALSE)
			.setPassive(Boolean.FALSE)
			.setBinding(endpoint.getBinding())
			.setAssertionConsumerService(
				serviceProviderMethods.getPreferredEndpoint(
					sp.getServiceProvider().getAssertionConsumerService(),
					null,
					preferredACSEndpointIndex
				)
			)
			.setIssuer(new Saml2Issuer().setValue(sp.getEntityId()))
			.setDestination(endpoint);
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		if (requestedNameId != null) {
			request.setNameIdPolicy(new Saml2NameIdPolicy(
				requestedNameId,
				sp.getEntityId(),
				true
			));
		}
		else if (idp.getDefaultNameId() != null) {
			request.setNameIdPolicy(new Saml2NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityId(),
				true
			));
		}
		else if (idp.getIdentityProvider().getNameIds().size() > 0) {
			request.setNameIdPolicy(new Saml2NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityId(),
				true
			));
		}
		return request;
	}

	private String getIdpAlias(HttpServletRequest request) {
		String path = request.getRequestURI().substring(request.getContextPath().length());
		if (!hasText(path)) {
			return null;
		}
		String[] paths = StringUtils.split(path, "/");
		if (paths.length < 3) {
			return null;
		}
		return paths[2];
	}


}
