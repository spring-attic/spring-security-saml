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

package org.springframework.security.saml.serviceprovider.web.filters;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

class StandaloneHtmlWriter {

	StandaloneHtmlWriter() {
	}

	void processHtmlBody(HttpServletResponse response, AbstractHtmlContent content) {
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		try {
			response.getWriter().write(content.getHtml());
		} catch (IOException e) {
			throw new SamlException(e);
		}
	}

}
