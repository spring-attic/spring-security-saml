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
 * Defines binding type as part of an Endpoint as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 8, Line 271
 */
public class Binding {

	public static final Binding POST = new Binding(BindingType.POST.toUri());
	public static final Binding REDIRECT = new Binding(BindingType.REDIRECT.toUri());
	public static final Binding URI = new Binding(BindingType.URI.toUri());
	public static final Binding ARTIFACT = new Binding(BindingType.ARTIFACT.toUri());
	public static final Binding POST_SIMPLE_SIGN = new Binding(BindingType.POST_SIMPLE_SIGN.toUri());
	public static final Binding PAOS = new Binding(BindingType.PAOS.toUri());
	public static final Binding SOAP = new Binding(BindingType.SOAP.toUri());
	public static final Binding DISCOVERY = new Binding(BindingType.DISCOVERY.toUri());
	public static final Binding REQUEST_INITIATOR = new Binding(BindingType.REQUEST_INITIATOR.toUri());
	public static final Binding SAML_1_0_BROWSER_POST = new Binding(BindingType.SAML_1_0_BROWSER_POST.toUri());
	public static final Binding SAML_1_0_BROWSER_ARTIFACT = new Binding(BindingType.SAML_1_0_BROWSER_ARTIFACT.toUri());

	private final java.net.URI value;
	private final BindingType type;

	protected Binding(String uri) throws URISyntaxException {
		this(new URI(uri));
	}

	public Binding(URI uri) {
		this(uri, BindingType.fromUrn(uri.toString()));
	}

	public Binding(URI uri, BindingType type) {
		this.value = uri;
		this.type = type;
	}


	public static Binding fromUrn(String other) {
		if (!hasText(other)) {
			return null;
		}
		try {
			return fromUrn(new URI(other));
		} catch (URISyntaxException e) {
			throw new SamlException(e);
		}
	}

	public static Binding fromUrn(URI other) {
		BindingType type = BindingType.fromUrn(other.toString());
		switch (type) {
			case REDIRECT: return Binding.REDIRECT;
			case POST: return Binding.POST;
			case URI: return Binding.URI;
			case ARTIFACT: return Binding.ARTIFACT;
			case POST_SIMPLE_SIGN: return Binding.POST_SIMPLE_SIGN;
			case PAOS: return Binding.PAOS;
			case SOAP: return Binding.SOAP;
			case DISCOVERY: return Binding.DISCOVERY;
			case REQUEST_INITIATOR: return Binding.REQUEST_INITIATOR;
			case SAML_1_0_BROWSER_ARTIFACT: return Binding.SAML_1_0_BROWSER_ARTIFACT;
			case SAML_1_0_BROWSER_POST: return Binding.SAML_1_0_BROWSER_POST;
			case CUSTOM: return new Binding(other, type);
		}
		throw new SamlException("Unknown binding type:"+other);
	}

	public java.net.URI getValue() {
		return value;
	}

	public BindingType getType() {
		return type;
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
		if (!(o instanceof Binding)) {
			return false;
		}

		Binding binding = (Binding) o;

		if (!getValue().equals(binding.getValue())) {
			return false;
		}
		return getType() == binding.getType();
	}

	@Override
	public int hashCode() {
		int result = getValue().hashCode();
		result = 31 * result + getType().hashCode();
		return result;
	}
}
