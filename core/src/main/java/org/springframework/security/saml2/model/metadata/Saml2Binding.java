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

/**
 * Defines binding type as part of an Endpoint as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 8, Line 271
 * This holds the actual value (in case of a custom binding) and the type
 */
public class Saml2Binding {

	public static final Saml2Binding POST = new Saml2Binding(Saml2BindingType.POST.toUri());
	public static final Saml2Binding REDIRECT = new Saml2Binding(Saml2BindingType.REDIRECT.toUri());
	public static final Saml2Binding URI = new Saml2Binding(Saml2BindingType.URI.toUri());
	public static final Saml2Binding ARTIFACT = new Saml2Binding(Saml2BindingType.ARTIFACT.toUri());
	public static final Saml2Binding POST_SIMPLE_SIGN = new Saml2Binding(Saml2BindingType.POST_SIMPLE_SIGN.toUri());
	public static final Saml2Binding PAOS = new Saml2Binding(Saml2BindingType.PAOS.toUri());
	public static final Saml2Binding SOAP = new Saml2Binding(Saml2BindingType.SOAP.toUri());
	public static final Saml2Binding DISCOVERY = new Saml2Binding(Saml2BindingType.DISCOVERY.toUri());
	public static final Saml2Binding REQUEST_INITIATOR = new Saml2Binding(Saml2BindingType.REQUEST_INITIATOR.toUri());
	public static final Saml2Binding SAML_1_0_BROWSER_POST = new Saml2Binding(Saml2BindingType.SAML_1_0_BROWSER_POST.toUri());
	public static final Saml2Binding SAML_1_0_BROWSER_ARTIFACT = new Saml2Binding(Saml2BindingType.SAML_1_0_BROWSER_ARTIFACT.toUri());

	private final java.net.URI value;
	private final Saml2BindingType type;

	protected Saml2Binding(String uri) throws URISyntaxException {
		this(new URI(uri));
	}

	public Saml2Binding(URI uri) {
		this(uri, Saml2BindingType.fromUrn(uri.toString()));
	}

	public Saml2Binding(URI uri, Saml2BindingType type) {
		this.value = uri;
		this.type = type;
	}

	public static Saml2Binding fromUrn(String other) {
		try {
			return fromUrn(new URI(other));
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
	}

	public static Saml2Binding fromUrn(URI uri) {
		if (uri == null) {
			return null;
		}

		Saml2BindingType type = Saml2BindingType.fromUrn(uri.toString());
		switch (type) {
			case REDIRECT: return Saml2Binding.REDIRECT;
			case POST: return Saml2Binding.POST;
			case URI: return Saml2Binding.URI;
			case ARTIFACT: return Saml2Binding.ARTIFACT;
			case POST_SIMPLE_SIGN: return Saml2Binding.POST_SIMPLE_SIGN;
			case PAOS: return Saml2Binding.PAOS;
			case SOAP: return Saml2Binding.SOAP;
			case DISCOVERY: return Saml2Binding.DISCOVERY;
			case REQUEST_INITIATOR: return Saml2Binding.REQUEST_INITIATOR;
			case SAML_1_0_BROWSER_ARTIFACT: return Saml2Binding.SAML_1_0_BROWSER_ARTIFACT;
			case SAML_1_0_BROWSER_POST: return Saml2Binding.SAML_1_0_BROWSER_POST;
			case CUSTOM: return new Saml2Binding(uri, type);
		}
		throw new Saml2Exception("Unknown binding type:"+uri.toString());
	}

	public java.net.URI getValue() {
		return value;
	}

	public Saml2BindingType getType() {
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
		if (!(o instanceof Saml2Binding)) {
			return false;
		}

		Saml2Binding binding = (Saml2Binding) o;

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
