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

package org.springframework.security.saml.serviceprovider.web.filters;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.configuration.ExternalProviderConfiguration;
import org.springframework.security.saml.configuration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.model.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.saml.util.StringUtils.stripSlashes;

/**
 * stow away this code for now.
 * some tests expect a dynamic IDP selection
 * this code will most likely be removed once those tests are converted
 */
public class DynamicSelectIdentityProviderFilter extends OncePerRequestFilter {

	private static Log logger = LogFactory.getLog(SamlLoginPageGeneratingFilter.class);

	private final String pathPrefix;
	private final RequestMatcher matcher;
	private final ServiceProviderResolver<HttpServletRequest> resolver;

	public DynamicSelectIdentityProviderFilter(String pathPrefix,
											   RequestMatcher matcher,
											   ServiceProviderResolver<HttpServletRequest> resolver) {
		this.pathPrefix = pathPrefix;
		this.matcher = matcher;
		this.resolver = resolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			generateLoginPage(request, response);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	protected void generateLoginPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HostedServiceProvider provider = resolver.getServiceProvider(request);
		HostedServiceProviderConfiguration configuration = provider.getConfiguration();
		Map<String, String> providerUrls = new HashMap<>();
		configuration.getProviders().stream().forEach(
			p -> {
				try {
					String linkText = p.getLinktext();
					String url = getAuthenticationRequestRedirectUrl(provider, p);
					providerUrls.put(linkText, url);
				} catch (Exception x) {
					logger.debug(
						format(
							"Unable to retrieve metadata for provider:%s with message:%s",
							p.getMetadata(),
							x.getMessage()
						),
						x
					);
				}
			}
		);
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		response.getWriter().write(getSelectIdpPage(providerUrls));
	}

	protected String getSelectIdpPage(Map<String, String> providers) {
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
								"            <a href=\"" + entry.getValue() + "\"><span style=\"font-weight:bold\">" +
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

	protected String getAuthenticationRequestRedirectUrl(HostedServiceProvider provider,
														 ExternalProviderConfiguration p) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(
			provider.getConfiguration().getBasePath()
		);
		builder.pathSegment(stripSlashes(pathPrefix) + "/authenticate");
		builder.pathSegment(UriUtils.encode(p.getAlias(), UTF_8.toString()));
		IdentityProviderMetadata metadata = provider.getRemoteProviders().get(p);
		//make sure provider is available
		if (metadata == null) {
			throw new SamlException("Unable to fetch metadata for alias:" + p.getAlias());
		}
		return builder.build().toUriString();
	}

}
