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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static org.springframework.util.StringUtils.hasText;

public class IdpInitiatedLoginFilter extends SamlFilter<IdentityProviderService> {

	private static Log logger = LogFactory.getLog(IdpInitiatedLoginFilter.class);

	private final SamlRequestMatcher requestMatcher;
	private final SamlMessageStore<Assertion, HttpServletRequest> assertionStore;
	private String postBindingTemplate = "/templates/saml2-post-binding.vm";

	public IdpInitiatedLoginFilter(SamlProviderProvisioning<IdentityProviderService> provisioning,
								   SamlMessageStore<Assertion, HttpServletRequest> assertionStore) {
		this(
			provisioning,
			assertionStore,
			new SamlRequestMatcher(provisioning, "init")
		);
	}

	public IdpInitiatedLoginFilter(SamlProviderProvisioning<IdentityProviderService> provisioning,
								   SamlMessageStore<Assertion, HttpServletRequest> assertionStore,
								   SamlRequestMatcher requestMatcher) {
		super(provisioning);
		this.requestMatcher = requestMatcher;
		this.assertionStore = assertionStore;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (requestMatcher.matches(request) &&
			authentication != null &&
			authentication.isAuthenticated()) {
			IdentityProviderService provider = getProvisioning().getHostedProvider();
			ServiceProviderMetadata recipient = getTargetProvider(request);
			AuthenticationRequest authenticationRequest = getAuthenticationRequest(request);
			Assertion assertion = getAssertion(authentication, provider, recipient);
			assertionStore.addMessage(request, assertion.getId(), assertion);
			Response r = provider.response(authenticationRequest, assertion, recipient);

			Endpoint acsUrl = provider.getPreferredEndpoint(
				recipient.getServiceProvider().getAssertionConsumerService(),
				Binding.POST,
				-1
			);

			logger.debug(
				format(
					"Sending assertion for SP:%s to URL:%s using Binding:%s",
					recipient.getEntityId(),
					acsUrl.getLocation(),
					acsUrl.getBinding()
				)
			);
			String relayState = request.getParameter("RelayState");
			if (acsUrl.getBinding() == Binding.REDIRECT) {
				String encoded = provider.toEncodedXml(r, true);
				UriComponentsBuilder url = UriComponentsBuilder.fromUriString(acsUrl.getLocation());
				url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
				if (hasText(relayState)) {
					url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
				}
				String redirect = url.build(true).toUriString();
				response.sendRedirect(redirect);
			}
			else if (acsUrl.getBinding() == Binding.POST) {
				String encoded = provider.toEncodedXml(r, false);
				Map<String, Object> model = new HashMap<>();
				model.put("action", acsUrl.getLocation());
				model.put("SAMLResponse", encoded);
				if (hasText(relayState)) {
					model.put("RelayState", relayState);
				}
				processHtml(request, response, getPostBindingTemplate(), model);
			}
			else {
				throw new SamlException("Unsupported binding:" + acsUrl.getBinding());
			}
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
		String entityId = request.getParameter("sp");
		return getProvisioning().getHostedProvider().getRemoteProvider(entityId);
	}

	protected AuthenticationRequest getAuthenticationRequest(HttpServletRequest request) {
		return null;
	}

	protected Assertion getAssertion(Authentication authentication,
									 IdentityProviderService provider,
									 ServiceProviderMetadata recipient) {
		return provider.assertion(recipient, authentication.getName(), NameId.PERSISTENT);
	}

	public String getPostBindingTemplate() {
		return postBindingTemplate;
	}

	public IdpInitiatedLoginFilter setPostBindingTemplate(String postBindingTemplate) {
		this.postBindingTemplate = postBindingTemplate;
		return this;
	}
}
