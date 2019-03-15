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
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ModelProvider;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.util.StringUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static org.springframework.util.StringUtils.hasText;

public class SelectServiceProviderFilter extends SamlFilter<IdentityProviderService> {

	private static Log logger = LogFactory.getLog(SelectServiceProviderFilter.class);
	private final RequestMatcher requestMatcher;
	private String selectTemplate = "/templates/spi/select-provider.vm";

	public SelectServiceProviderFilter(SamlProviderProvisioning<IdentityProviderService> provisioning) {
		this(
			provisioning,
			new SamlRequestMatcher(provisioning, "select")
		);
	}

	public SelectServiceProviderFilter(SamlProviderProvisioning<IdentityProviderService> provisioning,
									   RequestMatcher requestMatcher) {
		super(provisioning);
		this.requestMatcher = requestMatcher;
	}

	public String getSelectTemplate() {
		return selectTemplate;
	}

	public SelectServiceProviderFilter setSelectTemplate(String selectTemplate) {
		this.selectTemplate = selectTemplate;
		return this;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (requestMatcher.matches(request)) {
			List<ModelProvider> providers = new LinkedList<>();
			IdentityProviderService provider = getProvisioning().getHostedProvider();
			LocalIdentityProviderConfiguration configuration = provider.getConfiguration();

			configuration.getProviders().stream().forEach(
				p -> {
					try {
						ModelProvider mp =
							new ModelProvider()
								.setLinkText(p.getLinktext())
								.setRedirect(getIdpInitUrl(request, p));
						providers.add(mp);
					} catch (Exception x) {
						logger.debug(format(
							"Unable to retrieve metadata for provider:%s with message:",
							p.getMetadata(),
							x.getMessage()
							)
						);
					}
				}
			);
			Map<String, Object> model = new HashMap<>();
			model.put("title", "Select a Service Provider");
			model.put("providers", providers);
			processHtml(
				request,
				response,
				selectTemplate,
				model
			);
		}
		else {
			filterChain.doFilter(request, response);
		}

	}

	protected String getIdpInitUrl(HttpServletRequest request, ExternalProviderConfiguration p)
		throws UnsupportedEncodingException {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(
			getProvisioning().getHostedProvider().getConfiguration().getBasePath()
		);
		builder.pathSegment(getInitPath(request));
		IdentityProviderService provider = getProvisioning().getHostedProvider();
		ServiceProviderMetadata metadata = provider.getRemoteProvider(p);
		builder.queryParam("sp", UriUtils.encode(metadata.getEntityId(), StandardCharsets.UTF_8.toString()));
		return builder.build().toUriString();
	}

	private String getInitPath(HttpServletRequest request) {
		String ctxPath = request.getContextPath();
		String requestUri = request.getRequestURI();
		if (hasText(ctxPath)) {
			requestUri = requestUri.substring(ctxPath.length());
		}
		return StringUtils.stripStartingSlashes(requestUri.replace("/select", "/init"));
	}
}
