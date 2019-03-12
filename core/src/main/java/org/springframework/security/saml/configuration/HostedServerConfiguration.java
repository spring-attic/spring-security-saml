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

package org.springframework.security.saml.configuration;

/**
 * Represents a configuration for a host or domain.
 * A hosted domain can have one local service provider, or one local identity provider, or both.
 */
public class HostedServerConfiguration {

	private final HostedServiceProviderConfiguration serviceProvider;
	private final HostedIdentityProviderConfiguration identityProvider;

	public HostedServerConfiguration(HostedServiceProviderConfiguration serviceProvider,
									 HostedIdentityProviderConfiguration identityProvider) {
		this.serviceProvider = serviceProvider;
		this.identityProvider = identityProvider;
	}

	public HostedServiceProviderConfiguration getServiceProvider() {
		return serviceProvider;
	}

	public HostedIdentityProviderConfiguration getIdentityProvider() {
		return identityProvider;
	}

	public static final class Builder {
		private HostedServiceProviderConfiguration serviceProvider;
		private HostedIdentityProviderConfiguration identityProvider;

		private Builder() {
		}

		public static Builder builder() {
			return new Builder();
		}

		public static Builder builder(HostedServerConfiguration configuration) {
			return new Builder()
				.identityProvider(configuration.getIdentityProvider())
				.serviceProvider(configuration.getServiceProvider())
				;
		}

		public Builder serviceProvider(HostedServiceProviderConfiguration serviceProvider) {
			this.serviceProvider = serviceProvider;
			return this;
		}

		public Builder identityProvider(HostedIdentityProviderConfiguration identityProvider) {
			this.identityProvider = identityProvider;
			return this;
		}

		public HostedServerConfiguration build() {
			return new HostedServerConfiguration(serviceProvider, identityProvider);
		}
	}
}
