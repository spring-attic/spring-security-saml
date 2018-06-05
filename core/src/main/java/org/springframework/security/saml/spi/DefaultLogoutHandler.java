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

package org.springframework.security.saml.spi;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;

import static org.springframework.util.StringUtils.hasText;

public class DefaultLogoutHandler extends SamlMessageHandler<DefaultLogoutHandler> {

	private SamlValidator validator;
	private String postBindingTemplate;

	public SamlValidator getValidator() {
		return validator;
	}

	public DefaultLogoutHandler setValidator(SamlValidator validator) {
		this.validator = validator;
		return this;
	}

	public String getPostBindingTemplate() {
		return postBindingTemplate;
	}

	public DefaultLogoutHandler setPostBindingTemplate(String postBindingTemplate) {
		this.postBindingTemplate = postBindingTemplate;
		return this;
	}


	@Override
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {
		String prequest = request.getParameter("SAMLRequest");
		String presponse = request.getParameter("SAMLResponse");
		if (hasText(prequest)) {
			//we received a request
			LogoutRequest logoutRequest = (LogoutRequest) getTransformer().fromXml(prequest, null, null);
			return logoutRequested(logoutRequest, request, response);
		}
		else if (hasText(presponse)) {
			//we received a response
			LogoutResponse logoutResponse = (LogoutResponse) getTransformer().fromXml(presponse, null, null);
			return logoutCompleted(logoutResponse, request, response);
		}
		else {
			//the /logout URL was set, create request

		}
		return ProcessingStatus.STOP;
	}

	protected ProcessingStatus logoutCompleted(LogoutResponse logoutResponse,
											   HttpServletRequest request,
											   HttpServletResponse response) {
		return ProcessingStatus.CONTINUE;
	}

	protected ProcessingStatus logoutRequested(LogoutRequest logoutRequest,
											   HttpServletRequest request,
											   HttpServletResponse response) {

		return ProcessingStatus.STOP;
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalIdentityProviderConfiguration idp = getConfiguration().getIdentityProvider();
		String prefix = idp.getPrefix();
		String path = prefix + "/logout";
		return isUrlMatch(request, path);
	}
}
