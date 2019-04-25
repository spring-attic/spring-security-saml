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
import java.net.URLEncoder;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.provider.Saml2ServiceProviderInstance;
import org.springframework.security.saml2.serviceprovider.servlet.registration.Saml2ServiceProviderResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;

public class Saml2ServiceProviderMetadataFilter extends OncePerRequestFilter {

	private final Saml2ServiceProviderResolver providerResolver;
	private final Saml2Transformer transformer;
	private final RequestMatcher matcher;
	private String filename = "saml2-service-provider-metadata.xml";

	public Saml2ServiceProviderMetadataFilter(Saml2ServiceProviderResolver providerResolver,
											  Saml2Transformer transformer,
											  RequestMatcher matcher) {
		this.providerResolver = providerResolver;
		this.transformer = transformer;
		this.matcher = matcher;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			Saml2ServiceProviderInstance provider = providerResolver.getServiceProvider(request);
			logger.debug("Downloading SAML2 SP Metadata for:"+provider.getMetadata().getEntityId());
			String xml = transformer.toXml(provider.getMetadata());
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
