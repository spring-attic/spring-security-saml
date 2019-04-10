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

package org.springframework.security.saml2.serviceprovider.web.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.model.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.serviceprovider.model.Saml2HttpMessageData;
import org.springframework.security.saml2.serviceprovider.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class Saml2AuthenticationRequestResolvingFilter extends OncePerRequestFilter {

	private final Saml2AuthenticationRequestResolver resolver;
	private final RequestMatcher matcher;
	private final RedirectStrategy redirectStrategy;

	public Saml2AuthenticationRequestResolvingFilter(Saml2AuthenticationRequestResolver resolver,
													 RequestMatcher matcher) {
		this(resolver, matcher, new DefaultRedirectStrategy());
	}

	public Saml2AuthenticationRequestResolvingFilter(Saml2AuthenticationRequestResolver resolver,
													 RequestMatcher matcher,
													 RedirectStrategy redirectStrategy) {
		this.resolver = resolver;
		this.matcher = matcher;
		this.redirectStrategy = redirectStrategy;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			Saml2HttpMessageData mvcModel = resolveAuthenticationRequest(request);
			request.setAttribute(Saml2HttpMessageData.getModelAttributeName(), mvcModel);
		}
		filterChain.doFilter(request, response);
	}

	private Saml2HttpMessageData resolveAuthenticationRequest(HttpServletRequest request) {
		Saml2AuthenticationRequest authn = resolver.resolve(request);
		return new Saml2HttpMessageData(
			authn,
			null,
			authn.getDestination(),
			request.getParameter("RelayState")
		);
	}


}
