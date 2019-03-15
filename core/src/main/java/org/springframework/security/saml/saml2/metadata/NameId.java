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

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.security.saml.SamlException;

import static org.springframework.util.StringUtils.hasText;

/**
 * Attribute Name Format Identifiers
 */
public class NameId {

	public static final NameId UNSPECIFIED = new NameId(NameIdFormat.UNSPECIFIED.toUri());
	public static final NameId EMAIL = new NameId(NameIdFormat.EMAIL.toUri());
	public static final NameId TRANSIENT = new NameId(NameIdFormat.TRANSIENT.toUri());
	public static final NameId PERSISTENT = new NameId(NameIdFormat.PERSISTENT.toUri());
	public static final NameId X509_SUBJECT = new NameId(NameIdFormat.X509_SUBJECT.toUri());
	public static final NameId WIN_DOMAIN_QUALIFIED = new NameId(NameIdFormat.WIN_DOMAIN_QUALIFIED.toUri());
	public static final NameId KERBEROS = new NameId(NameIdFormat.KERBEROS.toUri());
	public static final NameId ENTITY = new NameId(NameIdFormat.ENTITY.toUri());
	public static final NameId ENCRYPTED = new NameId(NameIdFormat.ENCRYPTED.toUri());

	private final URI value;
	private final NameIdFormat format;

	protected NameId(String uri) throws URISyntaxException {
		this(new URI(uri));
	}

	public NameId(URI uri) {
		this(uri, NameIdFormat.fromUrn(uri.toString()));
	}

	public NameId(URI uri, NameIdFormat format) {
		this.value = uri;
		this.format = format;
	}

	public static NameId fromUrn(String other) {
		if (!hasText(other)) {
			return null;
		}

		URI uri;
		try {
			uri = new URI(other);
		} catch (URISyntaxException e) {
			throw new SamlException(e);
		}
		NameIdFormat format = NameIdFormat.fromUrn(other);
		switch (format) {
			case PERSISTENT: return PERSISTENT;
			case EMAIL: return EMAIL;
			case ENTITY: return ENTITY;
			case KERBEROS: return KERBEROS;
			case ENCRYPTED: return ENCRYPTED;
			case TRANSIENT: return TRANSIENT;
			case X509_SUBJECT: return X509_SUBJECT;
			case WIN_DOMAIN_QUALIFIED: return WIN_DOMAIN_QUALIFIED;
		}
		if (uri.equals(NameIdFormat.UNSPECIFIED.toUri())) {
			return UNSPECIFIED;
		}
		return new NameId(uri, NameIdFormat.UNSPECIFIED);
	}

	public URI getValue() {
		return value;
	}

	public NameIdFormat getFormat() {
		return format;
	}

	@Override
	public String toString() {
		return getValue().toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof NameId)) {
			return false;
		}

		NameId nameId = (NameId) o;

		if (!getValue().equals(nameId.getValue())) {
			return false;
		}
		return getFormat() == nameId.getFormat();
	}

	@Override
	public int hashCode() {
		int result = getValue().hashCode();
		result = 31 * result + getFormat().hashCode();
		return result;
	}
}
