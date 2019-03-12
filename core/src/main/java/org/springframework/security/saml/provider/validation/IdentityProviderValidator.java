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

package org.springframework.security.saml.provider.validation;

import java.util.List;

import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.provider.HostedIdentityProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.signature.Signature;

public interface IdentityProviderValidator {
	Signature validateSignature(SignableSaml2Object saml2Object, List<KeyData> verificationKeys);

	/**
	 * Performs an object validation on behalf of a service or identity provider on the respective object
	 *
	 * @param saml2Object the object to be validated according to SAML specification rules
	 * @param provider    the object used to resolve metadata
	 */
	ValidationResult validate(Saml2Object saml2Object, HostedIdentityProvider provider);
}
