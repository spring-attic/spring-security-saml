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

import org.springframework.security.saml.configuration.ExternalProviderConfiguration;
import org.springframework.security.saml.configuration.HostedProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.util.Assert;

public abstract class HostedProvider<
	Configuration extends HostedProviderConfiguration,
	LocalMetadata extends Metadata,
	RemoteConfiguration extends ExternalProviderConfiguration,
	RemoteMetadata extends Metadata> {

	private final Configuration configuration;
	private final LocalMetadata metadata;
	private final Map<RemoteConfiguration, RemoteMetadata> providers;

	protected HostedProvider(Configuration configuration,
							 LocalMetadata metadata,
							 Map<RemoteConfiguration, RemoteMetadata> providers) {
		this.configuration = configuration;
		this.metadata = metadata;
		this.providers = providers;
	}


	public Configuration getConfiguration() {
		return configuration;
	}

	public LocalMetadata getMetadata() {
		return metadata;
	}

	public Map<RemoteConfiguration,RemoteMetadata> getRemoteProviders() {
		return providers;
	}

	public RemoteMetadata getRemoteProvider(String entityId) {
		Assert.notNull(entityId, "Entity ID can not be null");
		return getRemoteProviders().entrySet().stream()
			.map(e -> e.getValue())
			.filter(p -> entityId.equals(p.getEntityId()))
			.findFirst()
			.orElse(null);
	}
}
