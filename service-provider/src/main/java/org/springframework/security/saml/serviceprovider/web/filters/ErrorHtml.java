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

import java.util.List;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

class ErrorHtml extends AbstractHtmlContent {
	public ErrorHtml(List<String> messages) {
		super(
			"<!DOCTYPE html>\n" +
				"<html>\n" +
				"<head>\n" +
				"    <meta charset=\"utf-8\" />\n" +
				"</head>\n" +
				"<body>\n" +
				"    <p>\n" +
				"        <strong>Error:</strong> A SAML error occurred<br/><br/>\n" +
				messages.stream().reduce((s1, s2) -> escapeHtml(s1) + "<br/>" + escapeHtml(s2)) +
				"    </p>\n" +
				"    #parse ( \"/templates/add-html-body-content.vm\" )\n" +
				"</body>\n" +
				"</html>"

		);
	}
}
