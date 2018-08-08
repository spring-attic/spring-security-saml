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

package org.springframework.security.saml.provider;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;

public class SamlMetadataFilter<ProviderType extends HostedProvider> extends OncePerRequestFilter {

	private final SamlProviderProvisioning<ProviderType> provisioning;
	private final RequestMatcher requestMatcher;
	private final String filename;
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

	public SamlMetadataFilter(SamlProviderProvisioning<ProviderType> provisioning) {
		this(provisioning, "saml-metadata.xml");
	}

	public SamlMetadataFilter(SamlProviderProvisioning<ProviderType> provisioning,
							  String filename) {
		this(
			provisioning,
			new SamlRequestMatcher(provisioning, "metadata", false),
			filename
		);
	}

	public SamlMetadataFilter(SamlProviderProvisioning<ProviderType> provisioning,
							  RequestMatcher requestMatcher,
							  String filename) {
		this.provisioning = provisioning;
		this.requestMatcher = requestMatcher;
		this.filename = filename;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (getRequestMatcher().matches(request)) {
			ProviderType provider = provisioning.getHostedProvider(request);
			Metadata metadata = provider.getMetadata();
			String xml = provider.toXml(metadata);
			response.setContentType(TEXT_XML_VALUE);
			response.addHeader(CONTENT_DISPOSITION, getFilename());
			getCacheHeaderWriter().writeHeaders(request, response);
			response.getWriter().write(xml);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private SamlProviderProvisioning<ProviderType> getProvisioning() {
		return provisioning;
	}

	private RequestMatcher getRequestMatcher() {
		return requestMatcher;
	}

	private String getFilename() {
		return filename;
	}

	private HeaderWriter getCacheHeaderWriter() {
		return cacheHeaderWriter;
	}
}
