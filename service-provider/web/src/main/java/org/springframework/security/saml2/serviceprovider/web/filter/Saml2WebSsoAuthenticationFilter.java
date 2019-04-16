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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.serviceprovider.web.authentication.Saml2AuthenticationTokenResolver;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Saml2WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static Log logger = LogFactory.getLog(Saml2WebSsoAuthenticationFilter.class);
	private final Saml2AuthenticationTokenResolver authenticationTokenResolver;
	private final RequestMatcher matcher;

	public Saml2WebSsoAuthenticationFilter(Saml2AuthenticationTokenResolver authenticationTokenResolver,
										   RequestMatcher matcher
	) {
		super(matcher);
		this.matcher = matcher;
		this.authenticationTokenResolver = authenticationTokenResolver;
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		setAuthenticationManager(authentication -> authentication);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return (
			matcher.matches(request) && request.getParameter("SAMLResponse")!=null
			);
	}



	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException {
		logger.debug("Attempting to resolve SAML2 WebSSO SAMLResponse");
		Authentication auth = authenticationTokenResolver.resolveSaml2Authentication(request, response);
		return getAuthenticationManager().authenticate(auth);
	}

}
