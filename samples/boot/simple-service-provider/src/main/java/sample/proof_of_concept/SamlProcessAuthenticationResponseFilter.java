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

package sample.proof_of_concept;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.saved_for_later.SamlValidator;
import org.springframework.security.saml.saved_for_later.ValidationException;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.util.Assert.notNull;
import static org.springframework.util.StringUtils.hasText;

public class SamlProcessAuthenticationResponseFilter extends AbstractAuthenticationProcessingFilter {
	private static Log logger = LogFactory.getLog(SamlProcessAuthenticationResponseFilter.class);
	private final SamlTransformer transformer;
	private final SamlValidator validator;
	private final StaticServiceProviderResolver resolver;

	public SamlProcessAuthenticationResponseFilter(SamlTransformer transformer,
												   SamlValidator validator,
												   StaticServiceProviderResolver resolver) {
		super(new AntPathRequestMatcher("/saml/sp/SSO/**"));
		this.transformer = transformer;
		this.validator = validator;
		this.resolver = resolver;
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		setAuthenticationManager(authentication -> authentication);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		Response samlResponse = super.requiresAuthentication(request, response) ? getSamlWebResponse(request,
			resolver.resolve(request)
		) : null;
		return samlResponse != null;
	}

	private Response getSamlWebResponse(HttpServletRequest request, HostedServiceProvider provider) {
		String samlResponseParameter = request.getParameter("SAMLResponse");
		Response result = null;
		if (hasText(samlResponseParameter)) {
			try {
				String decoded = transformer.samlDecode(
					samlResponseParameter,
					"GET".equalsIgnoreCase(request.getMethod())
				);
				result = (Response) transformer.fromXml(
					decoded,
					null,
					provider.getMetadata().getServiceProvider().getKeys()
				);
			} catch (Exception x) {
				logger.debug("Unable to parse response");
			}
		}
		else {
			logger.debug("SAMLResponse parameter is missing from request.");
		}
		return result;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException, IOException, ServletException {
		HostedServiceProvider provider = resolver.resolve(request);
		Response r = getSamlWebResponse(request, provider);
		notNull(r, "The response should never be null");
		IdentityProviderMetadata idp = getIdentityProvider(r, provider);
		if (idp == null) {
			logger.debug("Unable to find configured provider for SAML response.");
			return null;
		}
		try {
			Signature signature = validator.validateSignature(r, idp.getIdentityProvider().getKeys());
			r.setSignature(signature);
			for (Assertion assertion : r.getAssertions()) {
				signature = validator.validateSignature(assertion, idp.getIdentityProvider().getKeys());
				assertion.setSignature(signature);
			}
		} catch (SignatureException e) {
			logger.debug("Unable to validate signature for SAML response.");
			return null;
		}

		boolean authenticated = false;
		try {
			validator.validate(r, provider);
			authenticated = true;
		} catch (ValidationException e) {
			logger.debug("Unable to validate signature for SAML response.");
		}

		Assertion assertion = r.getAssertions().stream().findFirst().orElse(null);
		return new DefaultSamlAuthentication(
			authenticated,
			assertion,
			r.getOriginEntityId(),
			provider.getMetadata().getEntityId(),
			request.getParameter("RelayState")
		);
	}

	private IdentityProviderMetadata getIdentityProvider(Response r, HostedServiceProvider sp) {
		if (r.getAssertions().isEmpty()) {
			return null;
		}
		return sp.getRemoteProvider(r.getAssertions().get(0).getOriginEntityId());
	}


}
