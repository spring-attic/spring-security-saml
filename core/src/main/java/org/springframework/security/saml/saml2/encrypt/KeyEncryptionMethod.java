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

package org.springframework.security.saml.saml2.encrypt;

import javax.annotation.Nonnull;

public enum KeyEncryptionMethod {

	RSA_1_5("http://www.w3.org/2001/04/xmlenc#rsa-1_5"),
	RSA_OAEP_MGF1P("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");

	private final String urn;

	KeyEncryptionMethod(@Nonnull String urn) {
		this.urn = urn;
	}

	public static KeyEncryptionMethod fromUrn(String other) {
		for (KeyEncryptionMethod name : values()) {
			if (name.urn.equalsIgnoreCase(other)) {
				return name;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return this.urn;
	}
}
