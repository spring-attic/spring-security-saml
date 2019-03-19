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

package org.springframework.security.saml2.serviceprovider.web.filters;

import java.time.Clock;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.SamlProviderNotFoundException;
import org.springframework.security.saml2.configuration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml2.model.authentication.AuthenticationRequest;
import org.springframework.security.saml2.model.authentication.Issuer;
import org.springframework.security.saml2.model.authentication.NameIdPolicy;
import org.springframework.security.saml2.model.metadata.Binding;
import org.springframework.security.saml2.model.metadata.BindingType;
import org.springframework.security.saml2.model.metadata.Endpoint;
import org.springframework.security.saml2.model.metadata.IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.NameId;
import org.springframework.security.saml2.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml2.provider.HostedServiceProvider;
import org.springframework.security.saml2.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import org.joda.time.DateTime;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class Saml2WebAuthenticationRequestResolver
	implements Saml2AuthenticationRequestResolver<HttpServletRequest> {

	private Clock clock = Clock.systemUTC();
	private Saml2ServiceProviderMethods serviceProviderMethods;

	public Saml2WebAuthenticationRequestResolver(Saml2Transformer transformer,
												 ServiceProviderResolver resolver,
												 ServiceProviderValidator validator) {
		serviceProviderMethods = new Saml2ServiceProviderMethods(transformer, resolver, validator);
	}

	@Override
	public AuthenticationRequest resolve(HttpServletRequest request) {
		HostedServiceProvider provider = serviceProviderMethods.getProvider(request);
		Assert.notNull(provider, "Each request must resolve into a hosted SAML provider");
		Map.Entry<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> entity =
			getIdentityProvider(request, provider);
		ExternalIdentityProviderConfiguration idpConfig = entity.getKey();
		IdentityProviderMetadata idp = entity.getValue();
		ServiceProviderMetadata localSp = provider.getMetadata();
		final BindingType preferredSSOBinding =
			ofNullable(idpConfig.getAuthenticationRequestBinding())
				.orElse(Binding.REDIRECT)
				.getType();
		return getAuthenticationRequest(
			localSp,
			idp,
			idpConfig.getNameId(),
			idpConfig.getAssertionConsumerServiceIndex(),
			preferredSSOBinding
		);
	}

	@Override
	public String encode(AuthenticationRequest authn, boolean deflate) {
		String xml = serviceProviderMethods.getTransformer().toXml(authn);
		return serviceProviderMethods.getTransformer().samlEncode(xml, deflate);
	}

	/*
	 * UAA would want to override this as the entities are referred to by alias rather
	 * than ID
	 */
	protected Map.Entry<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> getIdentityProvider(
		HttpServletRequest request,
		HostedServiceProvider sp
	) {
		Map.Entry<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> result = null;
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
			throw new SamlProviderNotFoundException("Unable to identify a configured identity provider.");
		}
		return result;
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

	protected AuthenticationRequest getAuthenticationRequest(ServiceProviderMetadata sp,
															 IdentityProviderMetadata idp,
															 NameId requestedNameId,
															 int preferredACSEndpointIndex,
															 BindingType preferredSSOBinding) {
		Endpoint endpoint = serviceProviderMethods.getPreferredEndpoint(
			idp.getIdentityProvider().getSingleSignOnService(),
			preferredSSOBinding,
			-1
		);
		AuthenticationRequest request = new AuthenticationRequest()
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
			.setIssuer(new Issuer().setValue(sp.getEntityId()))
			.setDestination(endpoint);
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		if (requestedNameId != null) {
			request.setNameIdPolicy(new NameIdPolicy(
				requestedNameId,
				sp.getEntityId(),
				true
			));
		}
		else if (idp.getDefaultNameId() != null) {
			request.setNameIdPolicy(new NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityId(),
				true
			));
		}
		else if (idp.getIdentityProvider().getNameIds().size() > 0) {
			request.setNameIdPolicy(new NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityId(),
				true
			));
		}
		return request;
	}



}
