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

package org.springframework.security.saml2.model.authentication;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.util.Assert;

public enum Saml2SubjectConfirmationMethod {

	HOLDER_OF_KEY("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"),
	SENDER_VOUCHES("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"),
	BEARER("urn:oasis:names:tc:SAML:2.0:cm:bearer");


	private final String urn;

	Saml2SubjectConfirmationMethod(String urn) {
		Assert.notNull(urn, "URN cannot be null for enum: "+getClass().getSimpleName());
		this.urn = urn;
	}

	public static Saml2SubjectConfirmationMethod fromUrn(String other) {
		for (Saml2SubjectConfirmationMethod method : values()) {
			if (method.urn.equalsIgnoreCase(other)) {
				return method;
			}
		}
		throw new Saml2Exception("No SubjectConfirmationMethod enum for:" + other);
	}

	@Override
	public String toString() {
		return this.urn;
	}
}
