/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml.serviceprovider.web.filters;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.configuration.ExternalProviderConfiguration;
import org.springframework.security.saml.configuration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.serviceprovider.web.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.web.html.HtmlWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public class SelectIdentityProviderFilter extends AbstractSamlServiceProviderFilter {

	private static Log logger = LogFactory.getLog(SelectIdentityProviderFilter.class);

	private final String pathPrefix;
	private final HtmlWriter template;
	private String selectTemplate = "/templates/spi/select-provider.vm";
	private boolean redirectOnSingleProvider = true;

	public SelectIdentityProviderFilter(String pathPrefix,
										RequestMatcher matcher,
										HtmlWriter template,
										SamlTransformer transformer,
										ServiceProviderResolver resolver,
										ServiceProviderValidator validator) {
		super(transformer, resolver, validator, matcher);
		this.pathPrefix = pathPrefix;
		this.template = template;
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
		if (getMatcher().matches(request)) {
			HostedServiceProvider provider = getProvider(request);
			HostedServiceProviderConfiguration configuration = provider.getConfiguration();
			List<ModelProvider> providers = new LinkedList<>();
			configuration.getProviders().stream().forEach(
				p -> {
					try {
						ModelProvider mp = new ModelProvider()
							.setLinkText(p.getLinktext())
							.setRedirect(getAuthenticationRequestRedirectUrl(provider, p));
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
			if (providers.size() == 1 &&
				(isRedirectOnSingleProvider() || ("true".equalsIgnoreCase(request.getParameter("redirect"))))) {
				response.sendRedirect(providers.get(0).getRedirect());
			}
			else {
				Map<String, Object> model = new HashMap<>();
				model.put("title", "Select an Identity Provider");
				model.put("providers", providers);
				template.processHtmlBody(
					request,
					response,
					selectTemplate,
					model
				);
			}
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	protected String getAuthenticationRequestRedirectUrl(HostedServiceProvider provider,
														 ExternalProviderConfiguration p) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(
			provider.getConfiguration().getBasePath()
		);
		builder.pathSegment(stripSlashes(pathPrefix) + "/discovery");
		IdentityProviderMetadata metadata = provider.getRemoteProviders().get(p);
		builder.queryParam("idp", UriUtils.encode(metadata.getEntityId(), UTF_8.toString()));
		return builder.build().toUriString();
	}

	public boolean isRedirectOnSingleProvider() {
		return redirectOnSingleProvider;
	}

	public SelectIdentityProviderFilter setRedirectOnSingleProvider(boolean redirectOnSingleProvider) {
		this.redirectOnSingleProvider = redirectOnSingleProvider;
		return this;
	}

	public static class ModelProvider {
		private String linkText;
		private String redirect;

		public String getLinkText() {
			return linkText;
		}

		public ModelProvider setLinkText(String linkText) {
			this.linkText = linkText;
			return this;
		}

		public String getRedirect() {
			return redirect;
		}

		public ModelProvider setRedirect(String redirect) {
			this.redirect = redirect;
			return this;
		}
	}
}
