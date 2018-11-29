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

package org.springframework.security.saml;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.springframework.security.saml.provider.HostedProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;

import org.joda.time.DateTime;
import org.joda.time.Interval;

import static java.lang.String.format;
import static org.springframework.security.saml.saml2.metadata.NameId.ENTITY;

public interface SamlValidator<ProviderType extends HostedProvider> {

	SamlTransformer getSamlTransformer();

	/**
	 * Validates a signature on a SAML object. Returns the key that validated the signature
	 *
	 * @param saml2Object      - a signed object to validate
	 * @param verificationKeys a list of keys to use for validation
	 * @return the key that successfully validated the signature
	 * @throws SignatureException if object failed signature validation
	 */
	default Signature validateSignature(SignableSaml2Object saml2Object, List<KeyData> verificationKeys)
		throws SignatureException {
		try {
			return getSamlTransformer().validateSignature(saml2Object, verificationKeys);
		} catch (Exception x) {
			if (x instanceof SignatureException) {
				throw x;
			}
			else {
				throw new SignatureException(x.getMessage(), x);
			}
		}
	}

	/**
	 * Performs an object validation on behalf of a service or identity provider on the respective object
	 *
	 * @param saml2Object the object to be validated according to SAML specification rules
	 * @param provider    the object used to resolve metadata
	 */
	ValidationResult validate(Saml2Object saml2Object, ProviderType provider);

	default boolean isDateTimeSkewValid(int skewMillis, int forwardMillis, DateTime time) {
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

	default ValidationResult verifyIssuer(Issuer issuer, Metadata entity) {
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

	default boolean compareURIs(List<Endpoint> endpoints, String uri) {
		for (Endpoint ep : endpoints) {
			if (compareURIs(ep.getLocation(), uri)) {
				return true;
			}
		}
		return false;
	}

	default boolean compareURIs(String uri1, String uri2) {
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

	default String removeQueryString(String uri) {
		int queryStringIndex = uri.indexOf('?');
		if (queryStringIndex >= 0) {
			return uri.substring(0, queryStringIndex);
		}
		return uri;
	}
}
