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
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.security.saml.validation.ValidationResult;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.util.StringUtils.hasText;

public class SamlAuthenticationResponseFilter extends AbstractAuthenticationProcessingFilter {

	private static Log logger = LogFactory.getLog(SamlAuthenticationResponseFilter.class);

	private final SamlProviderProvisioning<ServiceProviderService> provisioning;

	public SamlAuthenticationResponseFilter(SamlProviderProvisioning<ServiceProviderService> provisioning) {
		this(new SamlRequestMatcher(provisioning, "SSO"), provisioning);
	}

	private SamlAuthenticationResponseFilter(RequestMatcher requiresAuthenticationRequestMatcher,
											 SamlProviderProvisioning<ServiceProviderService> provisioning) {
		super(requiresAuthenticationRequestMatcher);
		this.provisioning = provisioning;
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
	}



	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return
			hasText(getSamlResponseData(request)) &&
				super.requiresAuthentication(request, response);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException, IOException, ServletException {

		String responseData = getSamlResponseData(request);
		if (!hasText(responseData)) {
			throw new AuthenticationCredentialsNotFoundException("SAMLResponse parameter missing");
		}

		ServiceProviderService provider = getProvisioning().getHostedProvider();

		Response r = provider.fromXml(responseData, true, GET.matches(request.getMethod()), Response.class);
		if (logger.isTraceEnabled()) {
			logger.trace("Received SAMLResponse XML:" + r.getOriginalXML());
		}
		IdentityProviderMetadata remote = provider.getRemoteProvider(r);

		ValidationResult validationResult = provider.validate(r);
		if (validationResult.hasErrors()) {
			throw new InsufficientAuthenticationException(
				validationResult.toString()
			);
		}

		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			r.getAssertions().get(0),
			remote.getEntityId(),
			provider.getMetadata().getEntityId(),
			request.getParameter("RelayState")
		);
		authentication.setResponseXml(r.getOriginalXML());

		return getAuthenticationManager().authenticate(authentication);

	}

	private SamlProviderProvisioning<ServiceProviderService> getProvisioning() {
		return provisioning;
	}

	private String getSamlResponseData(HttpServletRequest request) {
		return request.getParameter("SAMLResponse");
	}

}
