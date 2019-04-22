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

package org.springframework.security.saml2.serviceprovider.servlet.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2Authentication;
import org.springframework.security.saml2.serviceprovider.binding.Saml2HttpMessageData;
import org.springframework.security.saml2.serviceprovider.servlet.binding.Saml2HttpMessageResponder;
import org.springframework.security.saml2.serviceprovider.servlet.logout.Saml2LogoutHttpMessageResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Saml2ServiceProviderLogoutFilter extends OncePerRequestFilter {

	private static Log logger = LogFactory.getLog(Saml2ServiceProviderLogoutFilter.class);

	private final RequestMatcher matcher;
	private final Saml2HttpMessageResponder saml2MessageResponder;
	private final Saml2LogoutHttpMessageResolver logoutResolver;
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private String defaultLogoutSuccessUrl = "/saml/sp/select";

	public Saml2ServiceProviderLogoutFilter(Saml2LogoutHttpMessageResolver logoutResolver,
											Saml2HttpMessageResponder saml2MessageResponder,
											RequestMatcher matcher) {
		this.matcher = matcher;
		this.logoutResolver = logoutResolver;
		this.saml2MessageResponder = saml2MessageResponder;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (matcher.matches(request)) {
			logger.debug("Processing SAML2 SP Logout.");
			if (authentication instanceof Saml2Authentication) {
				Saml2HttpMessageData data = logoutResolver.resolveLogoutHttpMessage(
					(Saml2Authentication) authentication,
					request,
					response
				);
				if (data == null) {
					logger.debug("No SAML2 Logout message needed. Performing regular logout.");
					doLogout(request, response, authentication, true);
				}
				else {
					//send either a LogoutRequest or a LogoutResponse to the IDP
					if (data.getSamlResponse() != null) {
						logger.debug("Sending SAML2 Logout Response. Performing local logout.");
						//clear the session locally
						doLogout(request, response, authentication, false);
					}
					else if (data.getSamlRequest() != null) {
						logger.debug("Sending SAML2 SP Logout Request.");
					}
					saml2MessageResponder.sendSaml2Message(data, request, response);
				}
			}
			else {
				logger.debug("SAML2 Logout Authentication missing. Performing regular logout.");
				doLogout(request, response, authentication, true);
			}
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private void doLogout(HttpServletRequest request,
						  HttpServletResponse response,
						  Authentication authentication,
						  boolean redirect) throws IOException {

		//TODO - this will be intercepted at the general /logout URL
		if (authentication != null) {
			SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
			logoutHandler.logout(request, response, authentication);
		}
		if (redirect) {
			//TODO - redirect to general app logout URL? /logout
			logger.debug("SAML2 SP Logout - redirecting to:" + defaultLogoutSuccessUrl);
			redirectStrategy.sendRedirect(request, response, defaultLogoutSuccessUrl);
		}
	}

}
