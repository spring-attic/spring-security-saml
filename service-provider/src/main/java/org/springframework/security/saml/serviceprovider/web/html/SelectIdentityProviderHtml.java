/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml.serviceprovider.web.html;

import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

public class SelectIdentityProviderHtml extends AbstractHtmlContent {
	public SelectIdentityProviderHtml(Map<String,String> providers) {
		super(
			"<html>\n" +
			"<head>\n" +
			"    <meta charset=\"utf-8\" />\n" +
			"</head>\n" +
			"<body>\n" +
			"<h1>Select an Identity Provider</h1>\n" +
			"<div>\n" +
			"    <ul>\n" +
				providers.entrySet().stream()
					.map(
						entry ->
							"        <li>\n" +
								"            <a href=\""+entry.getValue()+"\"><span style=\"font-weight:bold\">"+
								escapeHtml(entry.getKey()) + "</span></a>\n" +
								"        </li>\n"
					)
					.collect(Collectors.joining()) +
			"    </ul>\n" +
			"</div>\n" +
			"</body>\n" +
			"</html>"
		);
	}
}
