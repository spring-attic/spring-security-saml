/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml.provider.validation;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.provider.HostedProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;

import org.joda.time.DateTime;
import org.joda.time.Interval;

import static java.lang.String.format;
import static org.springframework.security.saml.saml2.metadata.NameId.ENTITY;

public abstract class AbstractSamlValidator<ProviderType extends HostedProvider> {

	final Signature INVALID_SIGNATURE = new Signature() {
		@Override
		public boolean isValidated() {
			return false;
		}
	};

	protected abstract SamlTransformer getSamlTransformer();

	protected abstract ValidationResult validate(Saml2Object saml2Object, ProviderType provider);
	/**
	 * Validates a signature on a SAML object. Returns the key that validated the signature
	 *
	 * @param saml2Object      - a signed object to validate
	 * @param verificationKeys a list of keys to use for validation
	 * @return the key that successfully validated the signature
	 * @throws SignatureException if object failed signature validation
	 */
	protected Signature validateSignature(SignableSaml2Object saml2Object, List<KeyData> verificationKeys)
		throws SignatureException {
		try {
			Signature main = getSamlTransformer().validateSignature(saml2Object, verificationKeys);
			if (saml2Object instanceof Response && main == null) {
				for (Assertion a : ((Response)saml2Object).getAssertions()) {
					try {
						Signature sig = getSamlTransformer().validateSignature(a, verificationKeys);
						a.setSignature(sig);
					} catch (SignatureException e){
						a.setSignature(INVALID_SIGNATURE);
					}
				}
			}
			saml2Object.setSignature(main);
			return main;
		} catch (Exception x) {
			if (x instanceof SignatureException) {
				throw x;
			}
			else {
				throw new SignatureException(x.getMessage(), x);
			}
		}
	}

	boolean isDateTimeSkewValid(int skewMillis, int forwardMillis, DateTime time) {
		if (time == null) {
			return false;
		}
		final DateTime reference = new DateTime();
		final Interval validTimeInterval = new Interval(
			reference.minusMillis(skewMillis + forwardMillis),
			reference.plusMillis(skewMillis)
		);
		return validTimeInterval.contains(time);
	}

	ValidationResult verifyIssuer(Issuer issuer, Metadata entity) {
		if (issuer != null) {
			if (!entity.getEntityId().equals(issuer.getValue())) {
				return new ValidationResult(entity)
					.addError(
						new ValidationResult.ValidationError(
							format(
								"Issuer mismatch. Expected: '%s' Actual: '%s'",
								entity.getEntityId(),
								issuer.getValue()
							)
						)
					);
			}
			if (issuer.getFormat() != null && !issuer.getFormat().equals(ENTITY)) {
				return new ValidationResult(entity)
					.addError(
						new ValidationResult.ValidationError(
							format(
								"Issuer name format mismatch. Expected: '%s' Actual: '%s'",
								ENTITY,
								issuer.getFormat()
							)
						)
					);
			}
		}
		return null;
	}

	boolean compareURIs(List<Endpoint> endpoints, String uri) {
		for (Endpoint ep : endpoints) {
			if (compareURIs(ep.getLocation(), uri)) {
				return true;
			}
		}
		return false;
	}

	boolean compareURIs(String uri1, String uri2) {
		if (uri1 == null && uri2 == null) {
			return true;
		}
		try {
			new URI(uri1);
			new URI(uri2);
			return removeQueryString(uri1).equalsIgnoreCase(removeQueryString(uri2));
		} catch (URISyntaxException e) {
			return false;
		}
	}

	String removeQueryString(String uri) {
		int queryStringIndex = uri.indexOf('?');
		if (queryStringIndex >= 0) {
			return uri.substring(0, queryStringIndex);
		}
		return uri;
	}

	ValidationResult validate(LogoutRequest logoutRequest, ProviderType provider) {
		ValidationResult result = new ValidationResult(logoutRequest);
		checkValidSignature(logoutRequest, result);
		return result;
	}

	ValidationResult validate(LogoutResponse logoutResponse, ProviderType provider) {
		ValidationResult result = new ValidationResult(logoutResponse);
		checkValidSignature(logoutResponse, result);
		return result;
	}

	void checkValidSignature(SignableSaml2Object saml2Object, ValidationResult result) {
		Signature signature = saml2Object.getSignature();
		if (signature != null && !signature.isValidated()) {
			result.addError(
				new ValidationResult.ValidationError("Invalid signature on "+saml2Object.getClass().getSimpleName())
			);
		}
	}

}
