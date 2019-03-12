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
package org.springframework.security.saml.saml2.signature;

public enum AlgorithmMethod {
	RSA_SHA1("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
	RSA_SHA256("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
	RSA_SHA512("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),
	RSA_RIPEMD160("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160");

	private final String urn;

	AlgorithmMethod(String urn) {
		this.urn = urn;
	}

	public static AlgorithmMethod fromUrn(String urn) {
		for (AlgorithmMethod m : values()) {
			if (m.urn.equalsIgnoreCase(urn)) {
				return m;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return urn;
	}
}
