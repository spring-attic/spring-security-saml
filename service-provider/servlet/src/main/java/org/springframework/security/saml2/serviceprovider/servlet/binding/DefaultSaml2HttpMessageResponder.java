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

package org.springframework.security.saml2.serviceprovider.servlet.binding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.http.Saml2HttpMessageData;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.util.StringUtils.hasText;

public class DefaultSaml2HttpMessageResponder implements Saml2HttpMessageResponder {

	private final Saml2Transformer transformer;
	private final RedirectStrategy redirectStrategy;

	public DefaultSaml2HttpMessageResponder(Saml2Transformer transformer,
											RedirectStrategy redirectStrategy) {
		this.transformer = transformer;
		this.redirectStrategy = redirectStrategy;
	}

	@Override
	public void sendSaml2Message(Saml2HttpMessageData model,
								 HttpServletRequest request,
								 HttpServletResponse response) throws IOException {
		String relayState = model.getRelayState();
		if (!hasText(relayState)) {
			relayState = request.getParameter("RelayState");
		}
		boolean deflate = Saml2Binding.REDIRECT.equals(model.getEndpoint().getBinding());
		String requestEncoded = getEncodedObject(model.getSamlRequest(), deflate);
		String responseEncoded = getEncodedObject(model.getSamlResponse(), deflate);
		if (Saml2Binding.REDIRECT.equals(model.getEndpoint().getBinding())) {
			UriComponentsBuilder url = UriComponentsBuilder.fromUriString(model.getEndpoint().getLocation());
			if (hasText(requestEncoded)) {
				url.queryParam("SAMLRequest", UriUtils.encode(requestEncoded, StandardCharsets.UTF_8.name()));
			}
			if (hasText(responseEncoded)) {
				url.queryParam("SAMLResponse", UriUtils.encode(responseEncoded, StandardCharsets.UTF_8.name()));
			}
			if (hasText(relayState)) {
				url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
			}
			String redirect = url.build(true).toUriString();
			redirectStrategy.sendRedirect(request, response, redirect);
		}
		else if (Saml2Binding.POST.equals(model.getEndpoint().getBinding())) {
			String html = postBindingHtml(
				model.getEndpoint().getLocation(),
				requestEncoded,
				responseEncoded,
				relayState
			);
			sendHtmlBody(response, html);
		}
		else {
			displayError(response, "Unsupported binding:" + model.getEndpoint().getBinding().toString());
		}
	}

	private String getEncodedObject(Saml2Object saml2Object, boolean deflate) {
		if (saml2Object == null) {
			return null;
		}
		String xml = transformer.toXml(saml2Object);
		return transformer.samlEncode(xml, deflate);
	}

	private String postBindingHtml(String postUrl,
								   String request,
								   String response,
								   String relayState) {

		return ("<!DOCTYPE html>\n" +
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
			"        <form action=\"" + postUrl + "\" method=\"post\">\n" +
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

	private void sendHtmlBody(HttpServletResponse response, String content) throws IOException {
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		response.getWriter().write(content);
	}

	private void displayError(HttpServletResponse response, String message) throws IOException {
		sendHtmlBody(response, errorHtml(Collections.singletonList(message)));
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
