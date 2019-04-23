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

package org.springframework.security.saml2.provider;

import java.util.Map;

import org.springframework.security.saml2.registration.ExternalSaml2IdentityProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;

/**
 * {@inheritDoc}
 */
public class Saml2ServiceProviderInstance extends AbstractSaml2ProviderInstance<
	HostedSaml2ServiceProviderRegistration,
	Saml2ServiceProviderMetadata,
	ExternalSaml2IdentityProviderRegistration,
	Saml2IdentityProviderMetadata> {

	public Saml2ServiceProviderInstance(HostedSaml2ServiceProviderRegistration registration,
										Saml2ServiceProviderMetadata metadata,
										Map<ExternalSaml2IdentityProviderRegistration, Saml2IdentityProviderMetadata> providers) {
		super(registration, metadata, providers);
	}
}
