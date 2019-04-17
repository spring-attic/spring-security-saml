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
import java.util.Collections;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

public class Saml2AuthenticationFailureHandler implements AuthenticationFailureHandler {

	private static Log logger = LogFactory.getLog(Saml2AuthenticationFailureHandler.class);

	public Saml2AuthenticationFailureHandler() {
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request,
										HttpServletResponse response,
										AuthenticationException exception) throws IOException, ServletException {
		logger.debug("Processing SAML2 Authentication Exception", exception);
		sendHtmlBody(response, errorHtml(Collections.singletonList(exception.getMessage())));
	}

	private void sendHtmlBody(HttpServletResponse response, String content) throws IOException {
		response.setStatus(400);
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		response.getWriter().write(content);
	}

	private String errorHtml(List<String> messages) {
		return (
			"<!DOCTYPE html>\n" +
				"<html>\n" +
				"<head>\n" +
				"    <meta charset=\"utf-8\" />\n" +
				"</head>\n" +
				"<body>\n" +
				"    <p>\n" +
				"        <strong>Error:</strong> A SAML error occurred<br/><br/>\n" +
				messages.stream().reduce((s1, s2) -> HtmlUtils.htmlEscape(s1) + "<br/>" + HtmlUtils.htmlEscape(s2)) +
				"    </p>\n" +
				"</body>\n" +
				"</html>"

		);
	}
}
