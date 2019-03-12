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

package org.springframework.security.saml.saml2.encrypt;

import java.lang.reflect.Field;

import org.springframework.security.saml.SamlException;
import org.springframework.util.Assert;

public enum DataEncryptionMethod {

	TRIPLEDES_CBS("http://www.w3.org/2001/04/xmlenc#tripledes-cbc"),
	AES128_CBC("http://www.w3.org/2001/04/xmlenc#aes128-cbc"),
	AES256_CBC("http://www.w3.org/2001/04/xmlenc#aes256-cbc"),
	AES192_CBC("http://www.w3.org/2001/04/xmlenc#aes192-cbc");

	private final String urn;

	DataEncryptionMethod(String urn) {
		Assert.notNull(urn, "URN cannot be null for enum: "+getClass().getSimpleName());
		this.urn = urn;
		try {
			Field fieldName = getClass().getSuperclass().getDeclaredField("name");
			fieldName.setAccessible(true);
			fieldName.set(this, urn);
			fieldName.setAccessible(false);
		} catch (Exception e) {
			throw new SamlException(e);
		}
	}

	public static DataEncryptionMethod fromUrn(String other) {
		for (DataEncryptionMethod name : values()) {
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
