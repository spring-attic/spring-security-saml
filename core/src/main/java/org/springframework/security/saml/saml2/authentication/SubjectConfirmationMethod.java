/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.saml2.authentication;

import javax.annotation.Nonnull;

import org.springframework.security.saml.SamlException;

public enum SubjectConfirmationMethod {

	HOLDER_OF_KEY("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"),
	SENDER_VOUCHES("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"),
	BEARER("urn:oasis:names:tc:SAML:2.0:cm:bearer");


	private final String urn;

	SubjectConfirmationMethod(@Nonnull String urn) {
		this.urn = urn;
	}

	public static SubjectConfirmationMethod fromUrn(String other) {
		for (SubjectConfirmationMethod method : values()) {
			if (method.urn.equalsIgnoreCase(other)) {
				return method;
			}
		}
		throw new SamlException("No SubjectConfirmationMethod enum for:" + other);
	}

	@Override
	public String toString() {
		return this.urn;
	}
}
