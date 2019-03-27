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
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.model.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.util.StringUtils.hasText;

public class Saml2AuthenticationRequestFilter extends OncePerRequestFilter {

	private final Saml2AuthenticationRequestResolver resolver;
	private final RequestMatcher matcher;
	private final RedirectStrategy redirectStrategy;

	public Saml2AuthenticationRequestFilter(Saml2AuthenticationRequestResolver resolver,
											RequestMatcher matcher) {
		this(resolver, matcher, new DefaultRedirectStrategy());
	}

	public Saml2AuthenticationRequestFilter(Saml2AuthenticationRequestResolver resolver,
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
			Saml2AuthenticationRequest authn = resolver.resolve(request);
			sendAuthenticationRequest(authn, authn.getDestination(), request, response);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	protected void sendAuthenticationRequest(Saml2AuthenticationRequest authn,
											 Saml2Endpoint destination,
											 HttpServletRequest request,
											 HttpServletResponse response) throws IOException {
		String relayState = request.getParameter("RelayState");
		if (destination.getBinding().equals(Saml2Binding.REDIRECT)) {
			String encoded = resolver.encode(authn, true);
			UriComponentsBuilder url = UriComponentsBuilder.fromUriString(destination.getLocation());
			url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
			if (hasText(relayState)) {
				url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
			}
			String redirect = url.build(true).toUriString();
			redirectStrategy.sendRedirect(request, response, redirect);
		}
		else if (destination.getBinding().equals(Saml2Binding.POST)) {
			String encoded = resolver.encode(authn, false);
			String html = postBindingHtml(destination.getLocation(), encoded, relayState);
			sendHtmlBody(response, html);
		}
		else {
			displayError(response, "Unsupported binding:" + destination.getBinding().toString());
		}
	}

	private void displayError(HttpServletResponse response, String message) throws IOException {
		sendHtmlBody(response, errorHtml(Collections.singletonList(message)));
	}

	private void sendHtmlBody(HttpServletResponse response, String content) throws IOException {
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		response.getWriter().write(content);
	}

	private String postBindingHtml(String postUrl,
								   String request,
								   String relayState) {

		return ("<!DOCTYPE html>\n" +
			"<html>\n" +
			"    <head>\n" +
			"        <meta charset=\"utf-8\" />\n" +
			"    </head>\n" +
			"    <body onload=\"document.forms[0].submit()\">\n" +
			"        <noscript>\n" +
			"            <p>\n" +
			"                <strong>Note:</strong> Since your browser does not support JavaScript,\n" +
			"                you must press the Continue button once to proceed.\n" +
			"            </p>\n" +
			"        </noscript>\n" +
			"        \n" +
			"        <form action=\""+ postUrl +"\" method=\"post\">\n" +
			"            <div>\n" +
			(hasText(relayState) ?
				("                <input type=\"hidden\" name=\"RelayState\" value=\"" +
					HtmlUtils.htmlEscape(relayState) +
					"\"/>\n"
				) : ""
			) +
			(hasText(request) ?
				("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"" +
					HtmlUtils.htmlEscape(request) +
					"\"/>\n"
				) : ""
			) +
			"            </div>\n" +
			"            <noscript>\n" +
			"                <div>\n" +
			"                    <input type=\"submit\" value=\"Continue\"/>\n" +
			"                </div>\n" +
			"            </noscript>\n" +
			"        </form>\n" +
			"    </body>\n" +
			"</html>");
	}

	private String errorHtml(List<String> messages) {
		return (
			"<!DOCTYPE html>\n" +
				"<html>\n" +
				"<head>\n" +
				"    <meta charset=\"utf-8\" />\n" +
				"</head>\n" +
				"<body>\n" +
				"    <p>\n" +
				"        <strong>Error:</strong> A SAML error occurred<br/><br/>\n" +
				messages.stream().reduce((s1, s2) -> HtmlUtils.htmlEscape(s1) + "<br/>" + HtmlUtils.htmlEscape(s2)) +
				"    </p>\n" +
				"    #parse ( \"/templates/add-html-body-content.vm\" )\n" +
				"</body>\n" +
				"</html>"

		);
	}
}
