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

package org.springframework.security.saml.saved_for_later;

import java.util.List;

import org.springframework.security.saml.provider.HostedIdentityProvider;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.key.SimpleKey;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;

public interface SamlValidator {
	/**
	 * Validates a signature on a SAML object. Returns the key that validated the signature
	 *
	 * @param saml2Object      - a signed object to validate
	 * @param verificationKeys a list of keys to use for validation
	 * @return the key that successfully validated the signature
	 * @throws SignatureException if object failed signature validation
	 */
	Signature validateSignature(Saml2Object saml2Object, List<SimpleKey> verificationKeys)
		throws SignatureException;

	/**
	 * Performs an object validation on behalf of a service provider on the respective object
	 *
	 * @param saml2Object the object to be validated according to SAML specification rules
	 * @param provider    the object used to resolve metadata
	 * @throws ValidationException if validation failed. Details in the exception.
	 */
	void validate(Saml2Object saml2Object, HostedServiceProvider provider) throws ValidationException;

	/**
	 * Performs an object validation on behalf of an identity provider on the respective object
	 *
	 * @param saml2Object the object to be validated according to SAML specification rules
	 * @param provider    the object used to resolve metadata
	 * @throws ValidationException if validation failed. Details in the exception.
	 */
	void validate(Saml2Object saml2Object, HostedIdentityProvider provider) throws ValidationException;

}
