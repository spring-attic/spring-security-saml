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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.SamlFilter;
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
public class SamlAuthenticationRequestFilter extends SamlFilter<ServiceProvider> {
	private final SamlProviderProvisioning<ServiceProvider> provisioning;
	private final RequestMatcher requestMatcher;
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();
	private String postTemplate = "/templates/saml2-post-binding.vm";

	public SamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProvider> provisioning) {
		this(provisioning, new SamlRequestMatcher(provisioning, "discovery", false));
	}


	public SamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProvider> provisioning,
										   RequestMatcher requestMatcher) {
		super(provisioning);
		this.provisioning = provisioning;
		this.requestMatcher = requestMatcher;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		String idpIdentifier = request.getParameter("idp");
		if (getRequestMatcher().matches(request) && hasText(idpIdentifier)) {
			ServiceProvider provider = provisioning.getHostedProvider(request);
			IdentityProviderMetadata idp = getIdentityProvider(provider, idpIdentifier);
			AuthenticationRequest authenticationRequest = provider.authenticationRequest(idp);
			String encoded = getEncodedAuthnRequestValue(provider, authenticationRequest);
			Endpoint location = provider.getSingleSignOnEndpoint();
			sendAuthenticationRequest(request, response, encoded, location);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	protected void sendAuthenticationRequest(HttpServletRequest request,
											 HttpServletResponse response,
											 String encoded,
											 Endpoint location) throws IOException {
		if (location.getBinding().equals(Binding.REDIRECT)) {
			UriComponentsBuilder url = UriComponentsBuilder.fromUriString(location.getLocation());
			url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
			String redirect = url.build(true).toUriString();
			response.sendRedirect(redirect);
		}
		else if (location.getBinding().equals(Binding.POST)) {
			processHtml(
				request,
				response,
				getPostTemplate(),
				Collections.singletonMap("SAMLRequest", encoded)
			);
		}
		else {
			processHtml(
				request,
				response,
				getErrorTemplate(),
				Collections.singletonMap("message", "Unsupported binding:"+location.getBinding().toString())
			);
		}
	}


	protected IdentityProviderMetadata getIdentityProvider(ServiceProvider provider, String idpIdentifier) {
		return provider.getRemoteProvider(idpIdentifier);
	}

	public SamlAuthenticationRequestFilter setCacheHeaderWriter(HeaderWriter cacheHeaderWriter) {
		this.cacheHeaderWriter = cacheHeaderWriter;
		return this;
	}

	public String getPostTemplate() {
		return postTemplate;
	}

	public SamlAuthenticationRequestFilter setPostTemplate(String postTemplate) {
		this.postTemplate = postTemplate;
		return this;
	}

	private String getEncodedAuthnRequestValue(ServiceProvider provider, AuthenticationRequest authenticationRequest)
		throws UnsupportedEncodingException {
		String xml = provider.toEncodedXml(authenticationRequest, true);
		return xml;
	}

	private RequestMatcher getRequestMatcher() {
		return requestMatcher;
	}

}
