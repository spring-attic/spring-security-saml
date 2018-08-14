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

package org.springframework.security.saml.provider.service.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlLogoutSuccessHandler;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.validation.ValidationResult;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static org.springframework.security.saml.provider.SamlLogoutSuccessHandler.RUN_SUCCESS;
import static org.springframework.util.StringUtils.hasText;

public class ServiceProviderLogoutHandler implements LogoutHandler {

	private static Log logger = LogFactory.getLog(ServiceProviderLogoutHandler.class);

	private final SamlProviderProvisioning<ServiceProvider> provisioning;

	public ServiceProviderLogoutHandler(SamlProviderProvisioning<ServiceProvider> provisioning) {
		this.provisioning = provisioning;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String logoutRequest = request.getParameter("SAMLRequest");
		String logoutResponse = request.getParameter("SAMLResponse");
		try {
			if (hasText(logoutRequest)) {
				receivedLogoutRequest(request, response, authentication, logoutRequest);
			}
			else if (hasText(logoutResponse)) {
				receivedLogoutResponse(request, response, authentication, logoutResponse);
			}
			else {
				spInitiatedLogout(request, response, authentication);
			}
		} catch (IOException x) {
			throw new SamlException(x);
		}
	}

	protected void receivedLogoutRequest(HttpServletRequest request,
									   HttpServletResponse response,
									   Authentication authentication,
									   String logoutRequest) throws IOException {
		ServiceProvider provider = provisioning.getHostedProvider(request);
		LogoutRequest lr = provider.fromXml(
			logoutRequest,
			true,
			HttpMethod.GET.name().equalsIgnoreCase(request.getMethod()),
			LogoutRequest.class
		);
		ValidationResult validate = provider.validate(lr);
		if (validate.hasErrors()) {
			throw new SamlException(validate.toString());
		}

		IdentityProviderMetadata idp = provider.getRemoteProvider(lr);
		LogoutResponse logoutResponse = provider.logoutResponse(lr, idp);
		String url = getRedirectUrl(provider, logoutResponse, logoutResponse.getDestination(), "SAMLResponse");
		response.sendRedirect(url);
		request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.REDIRECT);
	}

	protected void receivedLogoutResponse(HttpServletRequest request,
										HttpServletResponse response,
										Authentication authentication,
										String logoutResponse) {
		request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.SUCCESS);
	}

	protected void spInitiatedLogout(HttpServletRequest request,
									 HttpServletResponse response,
									 Authentication authentication) throws IOException {
		if (authentication instanceof SamlAuthentication) {
			SamlAuthentication sa = (SamlAuthentication)authentication;
			logger.debug(format("Initiating SP logout for SP:%s", sa.getHoldingEntityId()));
			ServiceProvider provider = provisioning.getHostedProvider(request);
			ServiceProviderMetadata sp = provider.getMetadata();
			IdentityProviderMetadata idp = provider.getRemoteProvider(sa.getAssertingEntityId());
			LogoutRequest lr = provider.logoutRequest(idp, (NameIdPrincipal) sa.getSamlPrincipal());
			if (lr.getDestination() != null) {
				logger.debug("Sending logout request through redirect.");
				String redirect = getRedirectUrl(provider, lr, lr.getDestination().getLocation(), "SAMLRequest");
				response.sendRedirect(redirect);
			}
			else {
				logger.debug("Unable to send logout request. No destination set.");
			}
		}
	}

	private String getRedirectUrl(ServiceProvider provider,
								  Saml2Object lr,
								  String location,
								  String paramName)
		throws UnsupportedEncodingException {
		String xml = provider.toXml(lr);
		String value = provider.toEncodedXml(xml, true);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
		return builder.queryParam(paramName, UriUtils.encode(value, StandardCharsets.UTF_8.name()))
			.build()
			.toUriString();
	}
}
