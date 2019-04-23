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

import org.springframework.security.saml2.registration.ExternalSaml2ServiceProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2IdentityProviderRegistration;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;

//TODO Move to Identity Provider module
public class HostedSaml2IdentityProvider extends HostedSaml2Provider<
	HostedSaml2IdentityProviderRegistration,
	Saml2IdentityProviderMetadata,
	ExternalSaml2ServiceProviderRegistration,
	Saml2ServiceProviderMetadata> {

	public HostedSaml2IdentityProvider(HostedSaml2IdentityProviderRegistration configuration,
									   Saml2IdentityProviderMetadata metadata,
									   Map<ExternalSaml2ServiceProviderRegistration, Saml2ServiceProviderMetadata> providers) {
		super(configuration, metadata, providers);
	}
}
