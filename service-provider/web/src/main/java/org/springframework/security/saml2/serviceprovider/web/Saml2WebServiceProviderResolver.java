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

package org.springframework.security.saml2.serviceprovider.web;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderConfigurationResolver;
import org.springframework.security.saml2.serviceprovider.metadata.Saml2ServiceProviderMetadataResolver;

public class Saml2WebServiceProviderResolver implements Saml2ServiceProviderResolver<HttpServletRequest> {

	private final Saml2ServiceProviderMetadataResolver metadataResolver;
	private final Saml2ServiceProviderConfigurationResolver configResolver;

	public Saml2WebServiceProviderResolver(Saml2ServiceProviderMetadataResolver metadataResolver,
										   Saml2ServiceProviderConfigurationResolver configResolver) {
		this.configResolver = configResolver;
		this.metadataResolver = metadataResolver;
	}

	@Override
	public HostedSaml2ServiceProvider getServiceProvider(HttpServletRequest request) {
		HostedSaml2ServiceProviderConfiguration config = configResolver.getConfiguration(request);
		return new HostedSaml2ServiceProvider(
			config,
			metadataResolver.getMetadata(config),
			metadataResolver.getIdentityProviders(config)
		);
	}

	@Override
	public String getConfiguredPathPrefix() {
		return configResolver.getConfiguredPathPrefix();
	}
}
