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

package org.springframework.security.saml.provider.service.authentication;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.HttpHeaders.CACHE_CONTROL;
import static org.springframework.http.HttpHeaders.PRAGMA;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

public class GenericErrorAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final SamlTemplateEngine engine;
	private final String template;

	public GenericErrorAuthenticationFailureHandler() {
		this(new OpenSamlVelocityEngine(), "/templates/spi/generic-error.vm");
	}

	public GenericErrorAuthenticationFailureHandler(SamlTemplateEngine engine, String template) {
		this.engine = engine;
		this.template = template;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request,
										HttpServletResponse response,
										AuthenticationException exception) throws IOException, ServletException {
		response.setStatus(HttpStatus.BAD_REQUEST.value());
		Map<String, Object> model = new HashMap<>();
		model.put("message", getErrorMessage(exception));
		processHtml(request, response, model);
	}

	protected String getErrorMessage(Exception exception) {
		return exception.getMessage();
	}

	protected void processHtml(HttpServletRequest request,
							   HttpServletResponse response,
							   Map<String, Object> model) {
		response.setHeader(CACHE_CONTROL, "no-cache, no-store");
		response.setHeader(PRAGMA, "no-cache");
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		StringWriter out = new StringWriter();
		getEngine().process(
			request,
			getTemplate(),
			model,
			out
		);
		try {
			response.getWriter().write(out.toString());
		} catch (IOException e) {
			throw new SamlException(e);
		}
	}

	public SamlTemplateEngine getEngine() {
		return engine;
	}

	public String getTemplate() {
		return template;
	}
}
