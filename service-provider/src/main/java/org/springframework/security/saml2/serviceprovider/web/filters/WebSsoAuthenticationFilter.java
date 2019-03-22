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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.Saml2ValidationResult;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2ResponseSaml2;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.signature.Signature;
import org.springframework.security.saml2.model.signature.SignatureException;
import org.springframework.security.saml2.serviceprovider.authentication.DefaultSamlAuthentication;
import org.springframework.security.saml2.serviceprovider.ServiceProviderResolver;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.util.Assert.notNull;

public class WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static Log logger = LogFactory.getLog(WebSsoAuthenticationFilter.class);
	private final ServiceProviderValidator validator;
	private final Saml2ServiceProviderMethods spUtils;

	public WebSsoAuthenticationFilter(Saml2Transformer transformer,
									  ServiceProviderResolver resolver,
									  ServiceProviderValidator validator,
									  RequestMatcher matcher
	) {
		super(matcher);
		this.validator = validator;
		this.spUtils = new Saml2ServiceProviderMethods(transformer, resolver, validator);
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		setAuthenticationManager(authentication -> authentication);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		Saml2ResponseSaml2 samlResponse = super.requiresAuthentication(request, response) ?
			getSamlWebResponse(request) :
			null;
		return samlResponse != null;
	}

	private Saml2ResponseSaml2 getSamlWebResponse(HttpServletRequest request) {
		Saml2Object object = spUtils.getSamlResponse(request);
		if (object == null) {
			return null;
		}
		if (object instanceof Saml2ResponseSaml2) {
			return (Saml2ResponseSaml2) object;
		}
		else {
			return null;
		}
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException {
		HostedSaml2ServiceProvider provider = spUtils.getProvider(request);
		Saml2ResponseSaml2 r = getSamlWebResponse(request);
		notNull(r, "The response should never be null");
		Saml2IdentityProviderMetadata idp = getIdentityProvider(r, provider);
		if (idp == null) {
			logger.debug("Unable to find configured provider for SAML response.");
			throw new ProviderNotFoundException(r.getIssuer().getValue());
		}
		try {
			Signature signature = validator.validateSignature(r, idp.getIdentityProvider().getKeys());
			r.setSignature(signature);
			for (Saml2Assertion assertion : r.getAssertions()) {
				if (assertion.getSignature() == null) {
					signature = validator.validateSignature(assertion, idp.getIdentityProvider().getKeys());
					assertion.setSignature(signature);
				}
			}
		} catch (SignatureException e) {
			logger.debug("Unable to validate signature for SAML response.");
			throw new AuthenticationServiceException("Failed to validate SAML authentication signature.");
		}

		Saml2ValidationResult validationResult = validator.validate(r, provider);
		if (!validationResult.isSuccess()) {
			throw new AuthenticationServiceException(validationResult.toString());
		}

		Saml2Assertion assertion = r.getAssertions().stream().findFirst().orElse(null);
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

	private Saml2IdentityProviderMetadata getIdentityProvider(Saml2ResponseSaml2 r, HostedSaml2ServiceProvider sp) {
		if (r.getAssertions().isEmpty()) {
			return null;
		}
		return sp.getRemoteProvider(r.getAssertions().get(0).getOriginEntityId());
	}

}
