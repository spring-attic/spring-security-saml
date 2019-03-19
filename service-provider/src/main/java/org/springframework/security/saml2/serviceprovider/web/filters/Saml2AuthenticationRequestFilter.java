/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml2.serviceprovider.web.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.SamlException;
import org.springframework.security.saml2.model.authentication.AuthenticationRequest;
import org.springframework.security.saml2.model.metadata.Binding;
import org.springframework.security.saml2.model.metadata.Endpoint;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.springframework.util.StringUtils.hasText;

public class Saml2AuthenticationRequestFilter extends OncePerRequestFilter {

	private final Saml2AuthenticationRequestResolver<HttpServletRequest> resolver;
	private final RequestMatcher matcher;
	private final StandaloneHtmlWriter writer = new StandaloneHtmlWriter();

	public Saml2AuthenticationRequestFilter(Saml2AuthenticationRequestResolver<HttpServletRequest> resolver,
											RequestMatcher matcher) {
		this.resolver = resolver;
		this.matcher = matcher;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			try {
				AuthenticationRequest authn = resolver.resolve(request);
				sendAuthenticationRequest(authn, authn.getDestination(), request, response);
			} catch (SamlException x) {
				displayError(response, x.getMessage());
			}
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	protected void sendAuthenticationRequest(AuthenticationRequest authn,
											 Endpoint destination,
											 HttpServletRequest request,
											 HttpServletResponse response) throws IOException {
		String relayState = request.getParameter("RelayState");
		if (destination.getBinding().equals(Binding.REDIRECT)) {
			String encoded = resolver.encode(authn, true);
			UriComponentsBuilder url = UriComponentsBuilder.fromUriString(destination.getLocation());
			url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
			if (hasText(relayState)) {
				url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
			}
			String redirect = url.build(true).toUriString();
			response.sendRedirect(redirect);
		}
		else if (destination.getBinding().equals(Binding.POST)) {
			String encoded = resolver.encode(authn, false);
			PostBindingHtml html = new PostBindingHtml(
				destination.getLocation(),
				encoded,
				null,
				relayState
			);
			writer.processHtmlBody(
				response,
				html
			);
		}
		else {
			displayError(response, "Unsupported binding:" + destination.getBinding().toString());
		}
	}

	private void displayError(HttpServletResponse response,
							  String message) {
		writer.processHtmlBody(
			response,
			new ErrorHtml(Collections.singletonList(message))
		);
	}

}
