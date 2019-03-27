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

package org.springframework.security.saml2.serviceprovider.web.filters;

import org.springframework.web.util.HtmlUtils;

import static org.springframework.util.StringUtils.hasText;

class PostBindingHtml extends AbstractHtmlContent {

	PostBindingHtml(String postUrl,
					String request,
					String response,
					String relayState) {

		super("<!DOCTYPE html>\n" +
			"<html>\n" +
			"    <head>\n" +
			"        <meta charset=\"utf-8\" />\n" +
			"    </head>\n" +
			"    <body onload=\"document.forms[0].submit()\">\n" +
			"        <noscript>\n" +
			"            <p>\n" +
			"                <strong>Note:</strong> Since your browser does not support JavaScript,\n" +
			"                you must press the Continue button once to proceed.\n" +
			"            </p>\n" +
			"        </noscript>\n" +
			"        \n" +
			"        <form action=\""+ postUrl +"\" method=\"post\">\n" +
			"            <div>\n" +
			(hasText(relayState) ?
				("                <input type=\"hidden\" name=\"RelayState\" value=\"" +
					HtmlUtils.htmlEscape(relayState) +
					"\"/>\n"
				) : ""
			) +
			(hasText(request) ?
				("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"" +
					HtmlUtils.htmlEscape(request) +
					"\"/>\n"
				) : ""
			) +
			(hasText(response) ?
				("                <input type=\"hidden\" name=\"SAMLResponse\" value=\"" +
					HtmlUtils.htmlEscape(response) +
					"\"/>\n"
				) : ""
			) +
			"            </div>\n" +
			"            <noscript>\n" +
			"                <div>\n" +
			"                    <input type=\"submit\" value=\"Continue\"/>\n" +
			"                </div>\n" +
			"            </noscript>\n" +
			"        </form>\n" +
			"    </body>\n" +
			"</html>");
	}
}
