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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.springframework.util.StringUtils.hasText;

/**
 * TODO - Error handling
 */
public class SamlAuthenticationRequestFilter extends SamlFilter<ServiceProviderService> {
	private final SamlProviderProvisioning<ServiceProviderService> provisioning;
	private final RequestMatcher requestMatcher;
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();
	private String postTemplate = "/templates/saml2-post-binding.vm";

	public SamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning) {
		this(provisioning, new SamlRequestMatcher(provisioning, "discovery", false));
	}


	public SamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
										   RequestMatcher requestMatcher) {
		super(provisioning);
		this.provisioning = provisioning;
		this.requestMatcher = requestMatcher;
	}

	private String getAuthnRequestXml(ServiceProviderService provider, AuthenticationRequest authenticationRequest) {
		String xml = provider.toXml(authenticationRequest);
		return xml;
	}

	public SamlAuthenticationRequestFilter setCacheHeaderWriter(HeaderWriter cacheHeaderWriter) {
		this.cacheHeaderWriter = cacheHeaderWriter;
		return this;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		String idpIdentifier = request.getParameter("idp");
		if (getRequestMatcher().matches(request) && hasText(idpIdentifier)) {
			ServiceProviderService provider = provisioning.getHostedProvider();
			IdentityProviderMetadata idp = getIdentityProvider(provider, idpIdentifier);
			AuthenticationRequest authenticationRequest = provider.authenticationRequest(idp);
			sendAuthenticationRequest(
				provider,
				request,
				response,
				authenticationRequest,
				authenticationRequest.getDestination()
			);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private RequestMatcher getRequestMatcher() {
		return requestMatcher;
	}

	protected IdentityProviderMetadata getIdentityProvider(ServiceProviderService provider, String idpIdentifier) {
		return provider.getRemoteProvider(idpIdentifier);
	}

	protected void sendAuthenticationRequest(ServiceProviderService provider,
											 HttpServletRequest request,
											 HttpServletResponse response,
											 AuthenticationRequest authenticationRequest,
											 Endpoint location) throws IOException {
		//TODO - send RelayState?
		String relayState = getRelayState(provider, request);
		if (location.getBinding().equals(Binding.REDIRECT)) {
			String encoded = provider.toEncodedXml(authenticationRequest, true);
			UriComponentsBuilder url = UriComponentsBuilder.fromUriString(location.getLocation());
			url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
			if (hasText(relayState)) {
				url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
			}
			String redirect = url.build(true).toUriString();
			response.sendRedirect(redirect);
		}
		else if (location.getBinding().equals(Binding.POST)) {
			String encoded = provider.toEncodedXml(authenticationRequest, false);
			Map<String, Object> model = new HashMap<>();
			model.put("action", location.getLocation());
			model.put("SAMLRequest", encoded);
			if (hasText(relayState)) {
				model.put("RelayState", relayState);
			}
			processHtml(
				request,
				response,
				getPostTemplate(),
				model
			);
		}
		else {
			processHtml(
				request,
				response,
				getErrorTemplate(),
				Collections.singletonMap("message", "Unsupported binding:" + location.getBinding().toString())
			);
		}
	}

	protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
		return null;
	}

	public String getPostTemplate() {
		return postTemplate;
	}

	public SamlAuthenticationRequestFilter setPostTemplate(String postTemplate) {
		this.postTemplate = postTemplate;
		return this;
	}

}
