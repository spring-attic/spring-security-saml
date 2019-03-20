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

package org.springframework.security.saml.provider;

import org.springframework.security.saml.provider.config.NetworkConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;

/**
 * Represents a configuration for a hosted or domain.
 * A hosted domain can have one local service provider, or one local identity provider, or both.
 */
public class SamlServerConfiguration implements Cloneable {

	private LocalServiceProviderConfiguration serviceProvider;
	private LocalIdentityProviderConfiguration identityProvider;
	private NetworkConfiguration network;

	public LocalServiceProviderConfiguration getServiceProvider() {
		return serviceProvider;
	}

	public SamlServerConfiguration setServiceProvider(LocalServiceProviderConfiguration serviceProvider) {
		this.serviceProvider = serviceProvider;
		return this;
	}

	public LocalIdentityProviderConfiguration getIdentityProvider() {
		return identityProvider;
	}

	public SamlServerConfiguration setIdentityProvider(LocalIdentityProviderConfiguration identityProvider) {
		this.identityProvider = identityProvider;
		return this;
	}

	public NetworkConfiguration getNetwork() {
		return network;
	}

	public SamlServerConfiguration setNetwork(NetworkConfiguration network) {
		this.network = network;
		return this;
	}

	@Override
	public SamlServerConfiguration clone() throws CloneNotSupportedException {
		SamlServerConfiguration result = (SamlServerConfiguration) super.clone();
		result.network = network != null ? network.clone() : null;
		result.identityProvider = identityProvider != null ? identityProvider.clone() : null;
		result.serviceProvider = serviceProvider != null ? serviceProvider.clone() : null;
		return result;
	}

	public SamlServerConfiguration transfer(SamlServerConfiguration external) {
		return this
			.setNetwork(external.getNetwork())
			.setIdentityProvider(external.getIdentityProvider())
			.setServiceProvider(external.getServiceProvider());
	}
}
