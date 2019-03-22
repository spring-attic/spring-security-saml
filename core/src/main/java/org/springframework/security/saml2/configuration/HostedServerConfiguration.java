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

package org.springframework.security.saml2.configuration;

/**
 * Represents a configuration for a host or domain.
 * A hosted domain can have one local service provider, or one local identity provider, or both.
 */
public class HostedServerConfiguration {

	private final HostedSaml2ServiceProviderConfiguration serviceProvider;
	private final HostedSaml2IdentityProviderConfiguration identityProvider;

	public HostedServerConfiguration(HostedSaml2ServiceProviderConfiguration serviceProvider,
									 HostedSaml2IdentityProviderConfiguration identityProvider) {
		this.serviceProvider = serviceProvider;
		this.identityProvider = identityProvider;
	}

	public HostedSaml2ServiceProviderConfiguration getServiceProvider() {
		return serviceProvider;
	}

	public HostedSaml2IdentityProviderConfiguration getIdentityProvider() {
		return identityProvider;
	}

	public static final class Builder {
		private HostedSaml2ServiceProviderConfiguration serviceProvider;
		private HostedSaml2IdentityProviderConfiguration identityProvider;

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

		public Builder serviceProvider(HostedSaml2ServiceProviderConfiguration serviceProvider) {
			this.serviceProvider = serviceProvider;
			return this;
		}

		public Builder identityProvider(HostedSaml2IdentityProviderConfiguration identityProvider) {
			this.identityProvider = identityProvider;
			return this;
		}

		public HostedServerConfiguration build() {
			return new HostedServerConfiguration(serviceProvider, identityProvider);
		}
	}
}
