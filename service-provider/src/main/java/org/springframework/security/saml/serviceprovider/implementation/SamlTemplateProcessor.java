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

package org.springframework.security.saml.serviceprovider.implementation;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

public class SamlTemplateProcessor {

	private final SamlTemplateEngine samlTemplateEngine;
	private String errorTemplate = "/templates/spi/generic-error.vm";
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

	public SamlTemplateProcessor(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
	}

	public void processHtmlBody(HttpServletRequest request,
								HttpServletResponse response,
								String html,
								Map<String, Object> model) {
		getCacheHeaderWriter().writeHeaders(request, response);
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		StringWriter out = new StringWriter();
		getSamlTemplateEngine().process(request, html, model, out);
		try {
			response.getWriter().write(out.toString());
		} catch (IOException e) {
			throw new SamlException(e);
		}
	}

	public SamlTemplateEngine getSamlTemplateEngine() {
		return samlTemplateEngine;
	}

	public String getErrorTemplate() {
		return errorTemplate;
	}

	public SamlTemplateProcessor setErrorTemplate(String errorTemplate) {
		this.errorTemplate = errorTemplate;
		return this;
	}

	public HeaderWriter getCacheHeaderWriter() {
		return cacheHeaderWriter;
	}

	public SamlTemplateProcessor setCacheHeaderWriter(HeaderWriter cacheHeaderWriter) {
		this.cacheHeaderWriter = cacheHeaderWriter;
		return this;
	}
}
