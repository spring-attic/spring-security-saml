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

package org.springframework.security.saml2.provider.validation;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.Saml2ValidationResult;
import org.springframework.security.saml2.provider.HostedSaml2Provider;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2LogoutSaml2Request;
import org.springframework.security.saml2.model.authentication.Saml2LogoutResponseSaml2;
import org.springframework.security.saml2.model.authentication.Saml2ResponseSaml2;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2Metadata;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;

import org.joda.time.DateTime;
import org.joda.time.Interval;

import static java.lang.String.format;
import static org.springframework.security.saml2.model.metadata.Saml2NameId.ENTITY;

abstract class AbstractSaml2Validator<ProviderType extends HostedSaml2Provider> {

	final Saml2Signature INVALID_SIGNATURE = new Saml2Signature() {
		@Override
		public boolean isValidated() {
			return false;
		}
	};

	protected abstract Saml2Transformer getSamlTransformer();

	protected abstract Saml2ValidationResult validate(Saml2Object saml2Object, ProviderType provider);
	/**
	 * Validates a signature on a SAML object. Returns the key that validated the signature
	 *
	 * @param saml2Object      - a signed object to validate
	 * @param verificationKeys a list of keys to use for validation
	 * @return the key that successfully validated the signature
	 * @throws Saml2SignatureException if object failed signature validation
	 */
	protected Saml2Signature validateSignature(Saml2SignableObject saml2Object, List<Saml2KeyData> verificationKeys)
		throws Saml2SignatureException {
		try {
			Saml2Signature main = getSamlTransformer().validateSignature(saml2Object, verificationKeys);
			if (saml2Object instanceof Saml2ResponseSaml2 && main == null) {
				for (Saml2Assertion a : ((Saml2ResponseSaml2)saml2Object).getAssertions()) {
					try {
						Saml2Signature sig = getSamlTransformer().validateSignature(a, verificationKeys);
						a.setSignature(sig);
					} catch (Saml2SignatureException e){
						a.setSignature(INVALID_SIGNATURE);
					}
				}
			}
			saml2Object.setSignature(main);
			return main;
		} catch (Exception x) {
			if (x instanceof Saml2SignatureException) {
				throw x;
			}
			else {
				throw new Saml2SignatureException(x.getMessage(), x);
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

	Saml2ValidationResult verifyIssuer(Saml2Issuer issuer, Saml2Metadata entity) {
		if (issuer != null) {
			if (!entity.getEntityId().equals(issuer.getValue())) {
				return new Saml2ValidationResult(entity)
					.addError(
						new Saml2ValidationResult.ValidationError(
							format(
								"Issuer mismatch. Expected: '%s' Actual: '%s'",
								entity.getEntityId(),
								issuer.getValue()
							)
						)
					);
			}
			if (issuer.getFormat() != null && !issuer.getFormat().equals(ENTITY)) {
				return new Saml2ValidationResult(entity)
					.addError(
						new Saml2ValidationResult.ValidationError(
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

	boolean compareURIs(List<Saml2Endpoint> endpoints, String uri) {
		for (Saml2Endpoint ep : endpoints) {
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

	Saml2ValidationResult validate(Saml2LogoutSaml2Request logoutRequest, ProviderType provider) {
		Saml2ValidationResult result = new Saml2ValidationResult(logoutRequest);
		checkValidSignature(logoutRequest, result);
		return result;
	}

	Saml2ValidationResult validate(Saml2LogoutResponseSaml2 logoutResponse, ProviderType provider) {
		Saml2ValidationResult result = new Saml2ValidationResult(logoutResponse);
		checkValidSignature(logoutResponse, result);
		return result;
	}

	void checkValidSignature(Saml2SignableObject saml2Object, Saml2ValidationResult result) {
		Saml2Signature signature = saml2Object.getSignature();
		if (signature != null && !signature.isValidated()) {
			result.addError(
				new Saml2ValidationResult.ValidationError("Invalid signature on "+saml2Object.getClass().getSimpleName())
			);
		}
	}

}
