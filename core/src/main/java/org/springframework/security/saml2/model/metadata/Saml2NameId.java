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

import org.springframework.security.saml2.Saml2Exception;

import static org.springframework.util.StringUtils.hasText;

/**
 * Attribute Name Format Identifiers
 */
public class Saml2NameId {

	public static final Saml2NameId UNSPECIFIED = new Saml2NameId(Saml2NameIdFormat.UNSPECIFIED.toUri());
	public static final Saml2NameId EMAIL = new Saml2NameId(Saml2NameIdFormat.EMAIL.toUri());
	public static final Saml2NameId TRANSIENT = new Saml2NameId(Saml2NameIdFormat.TRANSIENT.toUri());
	public static final Saml2NameId PERSISTENT = new Saml2NameId(Saml2NameIdFormat.PERSISTENT.toUri());
	public static final Saml2NameId X509_SUBJECT = new Saml2NameId(Saml2NameIdFormat.X509_SUBJECT.toUri());
	public static final Saml2NameId WIN_DOMAIN_QUALIFIED = new Saml2NameId(Saml2NameIdFormat.WIN_DOMAIN_QUALIFIED.toUri());
	public static final Saml2NameId KERBEROS = new Saml2NameId(Saml2NameIdFormat.KERBEROS.toUri());
	public static final Saml2NameId ENTITY = new Saml2NameId(Saml2NameIdFormat.ENTITY.toUri());
	public static final Saml2NameId ENCRYPTED = new Saml2NameId(Saml2NameIdFormat.ENCRYPTED.toUri());

	private final URI value;
	private final Saml2NameIdFormat format;

	protected Saml2NameId(String uri) throws URISyntaxException {
		this(new URI(uri));
	}

	public Saml2NameId(URI uri) {
		this(uri, Saml2NameIdFormat.fromUrn(uri.toString()));
	}

	public Saml2NameId(URI uri, Saml2NameIdFormat format) {
		this.value = uri;
		this.format = format;
	}

	public static Saml2NameId fromUrn(String other) {
		if (!hasText(other)) {
			return null;
		}

		try {
			return fromUrn(new URI(other));
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
	}

	public static Saml2NameId fromUrn(URI uri) {
		if (uri == null) {
			return null;
		}

		Saml2NameIdFormat format = Saml2NameIdFormat.fromUrn(uri);
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
		if (uri.equals(Saml2NameIdFormat.UNSPECIFIED.toUri())) {
			return UNSPECIFIED;
		}
		return new Saml2NameId(uri, Saml2NameIdFormat.UNSPECIFIED);
	}

	public URI getValue() {
		return value;
	}

	public Saml2NameIdFormat getFormat() {
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
		if (!(o instanceof Saml2NameId)) {
			return false;
		}

		Saml2NameId nameId = (Saml2NameId) o;

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
