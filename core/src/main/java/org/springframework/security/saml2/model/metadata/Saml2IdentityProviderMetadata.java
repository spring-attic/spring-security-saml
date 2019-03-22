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

/**
 * Represents metadata providing the IDPSSODescriptor entity
 */
public class Saml2IdentityProviderMetadata extends Saml2Metadata<Saml2IdentityProviderMetadata> {

	private Saml2NameId defaultNameId = null;

	public Saml2IdentityProviderMetadata() {
	}

	public Saml2IdentityProviderMetadata(Saml2IdentityProviderMetadata other) {
		super(other);
		this.defaultNameId = other.defaultNameId;
	}

	public Saml2IdentityProviderMetadata(Saml2Metadata other) {
		super(other);
	}

	public Saml2IdentityProvider getIdentityProvider() {
		return (Saml2IdentityProvider) getProviders()
			.stream()
			.filter(p -> p instanceof Saml2IdentityProvider)
			.findFirst()
			.get();

	}

	public Saml2NameId getDefaultNameId() {
		return defaultNameId;
	}

	public Saml2IdentityProviderMetadata setDefaultNameId(Saml2NameId defaultNameId) {
		this.defaultNameId = defaultNameId;
		return this;
	}
}
