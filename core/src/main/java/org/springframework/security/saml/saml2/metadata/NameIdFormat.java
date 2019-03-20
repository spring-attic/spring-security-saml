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

package org.springframework.security.saml.saml2.metadata;

import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import javax.annotation.Nonnull;

import org.springframework.security.saml.SamlException;
import org.springframework.util.Assert;

/**
 * Attribute Name Format Identifiers
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 82, Line 3528
 */
public enum NameIdFormat {

	UNSPECIFIED("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
	EMAIL("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
	TRANSIENT("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
	PERSISTENT("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
	X509_SUBJECT("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"),
	WIN_DOMAIN_QUALIFIED("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"),
	KERBEROS("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"),
	ENTITY("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),
	ENCRYPTED("urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted");

	private final String urn;

	NameIdFormat(@Nonnull String urn) {
		this.urn = urn;
		//Spring introspection calls valueOf(..) on enums
		//so we have to overwrite the name
		try {
			Field fieldName = getClass().getSuperclass().getDeclaredField("name");
			fieldName.setAccessible(true);
			fieldName.set(this, urn);
			fieldName.setAccessible(false);
		} catch (Exception e) {
			throw new SamlException(e);
		}
	}

	public static NameIdFormat fromUrn(String other) {
		Assert.notNull(other," NameIdFormat URN must not be null");
		for (NameIdFormat name : values()) {
			if (name.urn.equalsIgnoreCase(other)) {
				return name;
			}
		}
		return UNSPECIFIED;
	}

	@Override
	public String toString() {
		return this.urn;
	}

	public URI toUri() {
		try {
			return new URI(this.urn);
		} catch (URISyntaxException e) {
			throw new SamlException(e);
		}
	}
}
