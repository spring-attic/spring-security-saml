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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml.model.Saml2Object;
import org.springframework.security.saml.model.authentication.Assertion;
import org.springframework.security.saml.model.authentication.Response;
import org.springframework.security.saml.model.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.model.signature.Signature;
import org.springframework.security.saml.model.signature.SignatureException;
import org.springframework.security.saml.serviceprovider.authentication.DefaultSamlAuthentication;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.util.Assert.notNull;

public class WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static Log logger = LogFactory.getLog(WebSsoAuthenticationFilter.class);
	private final ServiceProviderValidator validator;
	private final SamlServiceProviderUtils spUtils;

	public WebSsoAuthenticationFilter(SamlTransformer transformer,
									  ServiceProviderResolver resolver,
									  ServiceProviderValidator validator,
									  RequestMatcher matcher
	) {
		super(matcher);
		this.validator = validator;
		this.spUtils = new SamlServiceProviderUtils(transformer, resolver, validator);
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		setAuthenticationManager(authentication -> authentication);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		Response samlResponse = super.requiresAuthentication(request, response) ?
			getSamlWebResponse(request) :
			null;
		return samlResponse != null;
	}

	private Response getSamlWebResponse(HttpServletRequest request) {
		Saml2Object object = spUtils.getSamlResponse(request);
		if (object == null) {
			return null;
		}
		if (object instanceof Response) {
			return (Response) object;
		}
		else {
			return null;
		}
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException {
		HostedServiceProvider provider = spUtils.getProvider(request);
		Response r = getSamlWebResponse(request);
		notNull(r, "The response should never be null");
		IdentityProviderMetadata idp = getIdentityProvider(r, provider);
		if (idp == null) {
			logger.debug("Unable to find configured provider for SAML response.");
			throw new ProviderNotFoundException(r.getIssuer().getValue());
		}
		try {
			Signature signature = validator.validateSignature(r, idp.getIdentityProvider().getKeys());
			r.setSignature(signature);
			for (Assertion assertion : r.getAssertions()) {
				if (assertion.getSignature() == null) {
					signature = validator.validateSignature(assertion, idp.getIdentityProvider().getKeys());
					assertion.setSignature(signature);
				}
			}
		} catch (SignatureException e) {
			logger.debug("Unable to validate signature for SAML response.");
			throw new AuthenticationServiceException("Failed to validate SAML authentication signature.");
		}

		ValidationResult validationResult = validator.validate(r, provider);
		if (!validationResult.isSuccess()) {
			throw new AuthenticationServiceException(validationResult.toString());
		}

		Assertion assertion = r.getAssertions().stream().findFirst().orElse(null);
		DefaultSamlAuthentication auth = new DefaultSamlAuthentication(
			true,
			assertion,
			r.getOriginEntityId(),
			provider.getMetadata().getEntityId(),
			request.getParameter("RelayState"),
			r.getOriginalXML()
		);
		return getAuthenticationManager().authenticate(auth);
	}

	private IdentityProviderMetadata getIdentityProvider(Response r, HostedServiceProvider sp) {
		if (r.getAssertions().isEmpty()) {
			return null;
		}
		return sp.getRemoteProvider(r.getAssertions().get(0).getOriginEntityId());
	}

}
