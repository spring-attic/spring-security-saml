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

package sample.proof_of_concept;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saved_for_later.HostedServiceProvider;

import sample.proof_of_concept.support_saved_for_later.ServiceProviderMetadataResolver;

public class StaticServiceProviderResolver {

	private final HostedServiceProviderConfiguration configuration;
	private final ServiceProviderMetadataResolver metadataResolver;


	public StaticServiceProviderResolver(ServiceProviderMetadataResolver metadataResolver,
										 HostedServiceProviderConfiguration configuration) {
		this.configuration = configuration;
		this.metadataResolver = metadataResolver;
	}

	public HostedServiceProvider resolve(HttpServletRequest request) {
		HostedServiceProviderConfiguration config = getConfiguration(request);
		return new HostedServiceProvider(
			config,
			metadataResolver.resolveHostedServiceProvider(request, config),
			metadataResolver.resolveConfiguredProviders(config)
		);
	}

	public HostedServiceProviderConfiguration getConfiguration(HttpServletRequest request) {
		return configuration;
	}
}
