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
import javax.annotation.Nonnull;

import org.springframework.security.saml.SamlException;
import org.springframework.util.Assert;

/**
 * Defines binding type as part of an Endpoint as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 8, Line 271
 */
public enum BindingType {

	POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
	REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
	URI("urn:oasis:names:tc:SAML:2.0:bindings:URI"),
	ARTIFACT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"),
	POST_SIMPLE_SIGN("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"),
	PAOS("urn:oasis:names:tc:SAML:2.0:bindings:PAOS"),
	SOAP("urn:oasis:names:tc:SAML:2.0:bindings:SOAP"),
	DISCOVERY("urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"),
	REQUEST_INITIATOR("urn:oasis:names:tc:SAML:profiles:SSO:request-init"),
	SAML_1_0_BROWSER_POST("urn:oasis:names:tc:SAML:1.0:profiles:browser-post"),
	SAML_1_0_BROWSER_ARTIFACT("urn:oasis:names:tc:SAML:1.0:profiles:artifact-01"),
	CUSTOM("urn:spring-security:SAML:2.0:custom"),;


	private final String urn;

	BindingType(@Nonnull String urn) {
		this.urn = urn;
	}

	public static BindingType fromUrn(String other) {
		Assert.notNull(other, "URN must not be null");
		for (BindingType binding : values()) {
			if (binding.urn.equalsIgnoreCase(other)) {
				return binding;
			}
		}
		return CUSTOM;
	}

	@Override
	public String toString() {
		return this.urn;
	}

	public java.net.URI toUri() {
		try {
			return new URI(urn);
		} catch (URISyntaxException e) {
			throw new SamlException(e);
		}
	}
}
