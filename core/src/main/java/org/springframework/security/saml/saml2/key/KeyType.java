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

package org.springframework.security.saml.saml2.key;

public enum KeyType {
	SIGNING("signing"),
	UNSPECIFIED("unspecified"),
	ENCRYPTION("encryption");

	private final String type;

	KeyType(String type) {
		this.type = type;
	}

	public static KeyType fromTypeName(String name) {
		for (KeyType t : values()) {
			if (t.getTypeName().equals(name)) {
				return t;
			}
		}
		return UNSPECIFIED;
	}

	public String getTypeName() {
		return type;
	}
}
