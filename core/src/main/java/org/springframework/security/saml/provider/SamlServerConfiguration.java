/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.provider;

import org.springframework.security.saml.provider.config.NetworkConfiguration;
import org.springframework.security.saml.provider.identity.config.HostedIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.HostedServiceProviderConfiguration;

/**
 * Represents a configuration for a hosted or domain.
 * A hosted domain can have one local service provider, or one local identity provider, or both.
 */
public class SamlServerConfiguration {

	private final HostedServiceProviderConfiguration serviceProvider;
	private final HostedIdentityProviderConfiguration identityProvider;
	private final NetworkConfiguration network;

	public SamlServerConfiguration(HostedServiceProviderConfiguration serviceProvider,
								   HostedIdentityProviderConfiguration identityProvider,
								   NetworkConfiguration network) {
		this.serviceProvider = serviceProvider;
		this.identityProvider = identityProvider;
		this.network = network;
	}

	public HostedServiceProviderConfiguration getServiceProvider() {
		return serviceProvider;
	}

	public HostedIdentityProviderConfiguration getIdentityProvider() {
		return identityProvider;
	}

	public NetworkConfiguration getNetwork() {
		return network;
	}

	public SamlServerConfiguration transfer(SamlServerConfiguration external) {
		return new SamlServerConfiguration(
			external.getServiceProvider(),
			external.getIdentityProvider(),
			external.getNetwork()
		);
	}
}
