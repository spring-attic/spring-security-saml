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

package org.springframework.security.saml2.serviceprovider.servlet.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.saml2.Saml2ValidationResult;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2Response;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.security.saml2.provider.Saml2ServiceProviderInstance;
import org.springframework.security.saml2.serviceprovider.authentication.DefaultSaml2Authentication;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2Authentication;
import org.springframework.security.saml2.serviceprovider.servlet.util.Saml2ServiceProviderMethods;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class DefaultSaml2AuthenticationTokenResolver implements Saml2AuthenticationTokenResolver {

	private static Log logger = LogFactory.getLog(DefaultSaml2AuthenticationTokenResolver.class);
	private final Saml2ServiceProviderMethods serviceProviderMethods;

	public DefaultSaml2AuthenticationTokenResolver(Saml2ServiceProviderMethods serviceProviderMethods) {
		this.serviceProviderMethods = serviceProviderMethods;
	}

	@Override
	public Saml2Authentication resolveSaml2Authentication(HttpServletRequest request,
														  HttpServletResponse response) {
		Saml2ServiceProviderInstance provider = serviceProviderMethods.getServiceProvider(request);
		Saml2Response r = getSamlWebResponse(request);
		Saml2IdentityProviderMetadata idp = getIdentityProvider(r, provider);
		try {
			Saml2Signature signature = serviceProviderMethods
				.getValidator()
				.validateSignature(r, idp.getIdentityProvider().getKeys());
			r.setSignature(signature);
			for (Saml2Assertion assertion : r.getAssertions()) {
				if (assertion.getSignature() == null) {
					signature = serviceProviderMethods
						.getValidator()
						.validateSignature(assertion, idp.getIdentityProvider().getKeys());
					assertion.setSignature(signature);
				}
			}
		} catch (Saml2SignatureException e) {
			logger.debug("Unable to validate signature for SAML response.");
			throw new AuthenticationServiceException("Failed to validate SAML authentication signature.");
		}

		Saml2ValidationResult validationResult = serviceProviderMethods
			.getValidator()
			.validate(r, provider);
		if (!validationResult.isSuccess()) {
			throw new AuthenticationServiceException(validationResult.toString());
		}

		Saml2Assertion assertion = r.getAssertions().stream().findFirst().orElse(null);

		return new DefaultSaml2Authentication(
			true,
			assertion,
			r.getOriginEntityId(),
			provider.getMetadata().getEntityId(),
			request.getParameter("RelayState"),
			r.getOriginalDataRepresentation()
		);
	}

	private Saml2Response getSamlWebResponse(HttpServletRequest request) {
		Saml2Object object = serviceProviderMethods.getSamlResponse(request);
		if (object == null) {
			return null;
		}
		if (object instanceof Saml2Response) {
			return (Saml2Response) object;
		}
		else {
			return null;
		}
	}

	private Saml2IdentityProviderMetadata getIdentityProvider(Saml2Response r, Saml2ServiceProviderInstance sp) {
		if (r.getAssertions().isEmpty()) {
			return null;
		}
		Saml2IdentityProviderMetadata idp = sp.getRemoteProvider(r.getAssertions().get(0).getOriginEntityId());
		if (idp == null) {
			logger.debug("Unable to find configured provider for SAML response.");
			throw new ProviderNotFoundException(r.getIssuer().getValue());
		}
		return idp;
	}

}
