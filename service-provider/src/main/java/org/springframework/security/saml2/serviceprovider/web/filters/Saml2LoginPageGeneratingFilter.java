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
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

/**
 * Filter that generates a static SAML SP login page.
 * It displays a list of identity providers whether they are online or not.
 */
public final class Saml2LoginPageGeneratingFilter extends OncePerRequestFilter {

	private final RequestMatcher matcher;
	private final Map<String, String> providerUrls;

	public Saml2LoginPageGeneratingFilter(RequestMatcher matcher,
										  Map<String, String> providerUrls) {
		this.matcher = matcher;
		this.providerUrls = providerUrls;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			response.setContentType(TEXT_HTML_VALUE);
			response.setCharacterEncoding(UTF_8.name());
			response.getWriter().write(getSaml2LoginPageHtml(providerUrls, request.getContextPath()));
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private String getSaml2LoginPageHtml(Map<String, String> providers, String contextPath) {
		return
			"<html>\n" +
				"<head>\n" +
				"    <meta charset=\"utf-8\" />\n" +
				"</head>\n" +
				"<body>\n" +
				"<h1>Select an Identity Provider</h1>\n" +
				"<div>\n" +
				"    <ul>\n" +
				providers.entrySet().stream()
					.map(
						entry ->
							"        <li>\n" +
								"            <a href=\"" + contextPath + entry.getValue() + "\"><span style=\"font-weight:bold\">" +
								HtmlUtils.htmlEscape(entry.getKey()) + "</span></a>\n" +
								"        </li>\n"
					)
					.collect(Collectors.joining()) +
				"    </ul>\n" +
				"</div>\n" +
				"</body>\n" +
				"</html>"
			;
	}
}
