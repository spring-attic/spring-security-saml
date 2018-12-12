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

package org.springframework.security.saml.serviceprovider.web.configuration;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;

import static org.springframework.util.Assert.notNull;
import static org.springframework.util.StringUtils.hasText;

public class SingletonServiceProviderConfigurationResolver implements ServiceProviderConfigurationResolver {

	private final HostedServiceProviderConfiguration configuration;

	public SingletonServiceProviderConfigurationResolver(HostedServiceProviderConfiguration configuration) {
		this.configuration = configuration;
		notNull(configuration, "HostedServiceProviderConfiguration must not be null");
		notNull(configuration.getPathPrefix(), "HostedServiceProviderConfiguration.pathPrefix must not be null");
	}

	@Override
	public String getConfiguredPathPrefix() {
		return configuration.getPathPrefix();
	}

	@Override
	public HostedServiceProviderConfiguration getConfiguration(HttpServletRequest request) {
		HostedServiceProviderConfiguration.Builder builder =
			HostedServiceProviderConfiguration.builder(configuration);
		String basePath = getBasePath(request, false);
		if (!hasText(configuration.getEntityId())) {
			builder.entityId(basePath);
		}
		if (!hasText(configuration.getAlias())) {
			builder.alias(request.getServerName());
		}
		if (!hasText(configuration.getBasePath())) {
			builder.basePath(basePath);
		}
		return builder.build();
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
