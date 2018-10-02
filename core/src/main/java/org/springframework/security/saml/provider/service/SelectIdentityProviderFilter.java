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
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.config.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

public class SelectIdentityProviderFilter extends SamlFilter<ServiceProviderService> {
	private static Log logger = LogFactory.getLog(SelectIdentityProviderFilter.class);

	private final RequestMatcher requestMatcher;
	private String selectTemplate = "/templates/spi/select-provider.vm";

	public SelectIdentityProviderFilter(SamlProviderProvisioning<ServiceProviderService> provisioning) {
		this(
			provisioning,
			new SamlRequestMatcher(provisioning, "select")
		);
	}

	public SelectIdentityProviderFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
										RequestMatcher requestMatcher) {
		super(provisioning);
		this.requestMatcher = requestMatcher;
	}

	public String getSelectTemplate() {
		return selectTemplate;
	}

	public SelectIdentityProviderFilter setSelectTemplate(String selectTemplate) {
		this.selectTemplate = selectTemplate;
		return this;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (requestMatcher.matches(request)) {
			ServiceProviderService provider = getProvisioning().getHostedProvider();
			HostedServiceProviderConfiguration configuration = provider.getConfiguration();
			List<ModelProvider> providers = new LinkedList<>();
			configuration.getProviders().stream().forEach(
				p -> {
					try {
						ModelProvider mp = new ModelProvider()
							.setLinkText(p.getLinktext())
							.setRedirect(getDiscoveryRedirect(provider, request, p));
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
			model.put("title", "Select an Identity Provider");
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

	protected String getDiscoveryRedirect(ServiceProviderService provider,
										  HttpServletRequest request,
										  ExternalProviderConfiguration p) throws UnsupportedEncodingException {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(
			provider.getConfiguration().getBasePath()
		);
		builder.pathSegment("saml/sp/discovery");
		IdentityProviderMetadata metadata = provider.getRemoteProvider(p);
		builder.queryParam("idp", UriUtils.encode(metadata.getEntityId(), UTF_8.toString()));
		return builder.build().toUriString();
	}
}
