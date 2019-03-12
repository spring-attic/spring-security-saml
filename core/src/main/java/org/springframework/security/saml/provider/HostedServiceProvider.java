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

package org.springframework.security.saml.provider;

import java.util.Map;

import org.springframework.security.saml.configuration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.configuration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

public class HostedServiceProvider extends HostedProvider<
	HostedServiceProviderConfiguration,
	ServiceProviderMetadata,
	ExternalIdentityProviderConfiguration,
	IdentityProviderMetadata> {

	public HostedServiceProvider(HostedServiceProviderConfiguration configuration,
								 ServiceProviderMetadata metadata,
								 Map<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> providers) {
		super(configuration, metadata, providers);
	}
}
