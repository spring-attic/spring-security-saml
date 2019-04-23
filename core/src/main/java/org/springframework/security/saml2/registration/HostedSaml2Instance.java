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

package org.springframework.security.saml2.registration;

/**
 * Represents a configuration for a host or domain.
 * A hosted domain can have one local service provider, or one local identity provider, or both.
 */
public class HostedSaml2Instance {

	private final HostedSaml2ServiceProviderRegistration serviceProvider;
	private final HostedSaml2IdentityProviderRegistration identityProvider;

	public HostedSaml2Instance(HostedSaml2ServiceProviderRegistration serviceProvider,
							   HostedSaml2IdentityProviderRegistration identityProvider) {
		this.serviceProvider = serviceProvider;
		this.identityProvider = identityProvider;
	}

	public HostedSaml2ServiceProviderRegistration getServiceProvider() {
		return serviceProvider;
	}

	public HostedSaml2IdentityProviderRegistration getIdentityProvider() {
		return identityProvider;
	}

	public static final class Builder {
		private HostedSaml2ServiceProviderRegistration serviceProvider;
		private HostedSaml2IdentityProviderRegistration identityProvider;

		private Builder() {
		}

		public static Builder builder() {
			return new Builder();
		}

		public static Builder builder(HostedSaml2Instance instance) {
			return new Builder()
				.identityProvider(instance.getIdentityProvider())
				.serviceProvider(instance.getServiceProvider())
				;
		}

		public Builder serviceProvider(HostedSaml2ServiceProviderRegistration serviceProvider) {
			this.serviceProvider = serviceProvider;
			return this;
		}

		public Builder identityProvider(HostedSaml2IdentityProviderRegistration identityProvider) {
			this.identityProvider = identityProvider;
			return this;
		}

		public HostedSaml2Instance build() {
			return new HostedSaml2Instance(serviceProvider, identityProvider);
		}
	}
}
