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

package org.springframework.security.saml.provider;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.web.filter.OncePerRequestFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

public abstract class SamlFilter<T extends HostedProviderService> extends OncePerRequestFilter {

	private static Log logger = LogFactory.getLog(SamlFilter.class);
	private final SamlProviderProvisioning<T> provisioning;
	private String errorTemplate = "/templates/spi/generic-error.vm";
	private SamlTemplateEngine samlTemplateEngine = new OpenSamlVelocityEngine();
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

	protected SamlFilter(SamlProviderProvisioning<T> provisioning) {
		this.provisioning = provisioning;
	}

	public String getErrorTemplate() {
		return errorTemplate;
	}

	public SamlFilter setErrorTemplate(String errorTemplate) {
		this.errorTemplate = errorTemplate;
		return this;
	}

	public SamlProviderProvisioning<T> getProvisioning() {
		return provisioning;
	}

	public HeaderWriter getCacheHeaderWriter() {
		return cacheHeaderWriter;
	}

	protected void processHtml(HttpServletRequest request,
							   HttpServletResponse response,
							   String html,
							   Map<String, Object> model) {
		cacheHeaderWriter.writeHeaders(request, response);
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		StringWriter out = new StringWriter();
		getSamlTemplateEngine().process(
			request,
			html,
			model,
			out
		);
		try {
			response.getWriter().write(out.toString());
		} catch (IOException e) {
			throw new SamlException(e);
		}
	}

	public SamlTemplateEngine getSamlTemplateEngine() {
		return samlTemplateEngine;
	}

	public SamlFilter setSamlTemplateEngine(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
		return this;
	}
}
