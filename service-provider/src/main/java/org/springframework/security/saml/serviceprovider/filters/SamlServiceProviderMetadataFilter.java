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

package org.springframework.security.saml.serviceprovider.filters;

import java.io.IOException;
import java.net.URLEncoder;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.serviceprovider.HostedServiceProvider;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;

public class SamlServiceProviderMetadataFilter extends OncePerRequestFilter
	implements Filter, SamlFilter<HostedServiceProvider> {

	private final SamlTransformer transformer;

	private final AntPathRequestMatcher matcher;
	private String filename = "saml-service-provider-metadata.xml";
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

	public SamlServiceProviderMetadataFilter(AntPathRequestMatcher matcher,
											 SamlTransformer transformer) {
		this.transformer = transformer;
		this.matcher = matcher;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			HostedServiceProvider provider = getProvider(request);
			String xml = transformer.toXml(provider.getMetadata());
			cacheHeaderWriter.writeHeaders(request, response);
			response.setContentType(TEXT_XML_VALUE);
			String safeFilename = URLEncoder.encode(filename, "ISO-8859-1");
			response.addHeader(CONTENT_DISPOSITION, "attachment; filename=\"" + safeFilename + "\"" + ";");
			response.getWriter().write(xml);
		}
		else {
			chain.doFilter(request, response);
		}
	}
}
