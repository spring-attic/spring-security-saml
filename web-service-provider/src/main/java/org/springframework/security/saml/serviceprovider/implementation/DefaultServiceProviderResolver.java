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

package org.springframework.security.saml.serviceprovider.implementation;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.SpConfigurationResolver;

import static org.springframework.util.StringUtils.hasText;

public class DefaultServiceProviderResolver implements ServiceProviderResolver {

	private final SpConfigurationResolver configuration;
	private final ServiceProviderMetadataResolver metadataResolver;

	public DefaultServiceProviderResolver(ServiceProviderMetadataResolver metadataResolver,
										  SpConfigurationResolver configuration) {
		this.configuration = configuration;
		this.metadataResolver = metadataResolver;
	}

	@Override
	public HostedServiceProvider resolve(HttpServletRequest request) {
		HostedServiceProviderConfiguration config = configuration.resolve(request);
		if (!hasText(config.getBasePath())) {
			config = HostedServiceProviderConfiguration.Builder.builder(config)
				.withBasePath(getBasePath(request, false))
				.build();
		}
		return new HostedServiceProvider(
			config,
			metadataResolver.resolveHostedServiceProvider(config),
			metadataResolver.resolveConfiguredProviders(config)
		);
	}

	private String getBasePath(HttpServletRequest request, boolean includeStandardPorts) {
		boolean includePort = true;
		if (443 == request.getServerPort() && "https".equals(request.getScheme())) {
			includePort = includeStandardPorts;
		}
		else if (80 == request.getServerPort() && "http".equals(request.getScheme())) {
			includePort = includeStandardPorts;
		}
		return request.getScheme() +
			"://" +
			request.getServerName() +
			(includePort ? (":" + request.getServerPort()) : "") +
			request.getContextPath();
	}
}
