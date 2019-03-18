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

package org.springframework.security.saml2.model.metadata;

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.security.saml2.SamlException;
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

	NameIdFormat(String urn) {
		Assert.notNull(urn, "URN must not be null");
		this.urn = urn;
	}

	public static NameIdFormat fromUrn(URI other) {
		Assert.notNull(other," NameIdFormat URN must not be null");
		return fromUrn(other.toString());
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
