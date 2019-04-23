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

package org.springframework.security.saml2.serviceprovider.servlet.registration;

import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration.Builder;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderRegistrationResolver;

import static org.springframework.util.Assert.notNull;
import static org.springframework.util.StringUtils.hasText;

public class SingletonSaml2ServiceProviderRegistrationResolver
	implements Saml2ServiceProviderRegistrationResolver<HttpServletRequest> {

	private final HostedSaml2ServiceProviderRegistration registration;

	public SingletonSaml2ServiceProviderRegistrationResolver(HostedSaml2ServiceProviderRegistration registration) {
		this.registration = registration;
		notNull(registration, "HostedServiceProviderRegistration must not be null");
		notNull(registration.getPathPrefix(), "HostedServiceProviderRegistration.pathPrefix must not be null");
	}

	public static SingletonSaml2ServiceProviderRegistrationResolver fromConfiguration(Consumer<Builder> config) {
		Builder builder = HostedSaml2ServiceProviderRegistration.builder();
		config.accept(builder);
		return fromConfiguration(builder.build());
	}

	public static SingletonSaml2ServiceProviderRegistrationResolver fromConfiguration(
		HostedSaml2ServiceProviderRegistration c) {
		return new SingletonSaml2ServiceProviderRegistrationResolver(c);
	}

	@Override
	public HostedSaml2ServiceProviderRegistration getServiceProviderRegistration(HttpServletRequest request) {
		Builder builder =
			HostedSaml2ServiceProviderRegistration.builder(registration);
		if (request != null) {
			String basePath = getBasePath(request, false);
			if (!hasText(registration.getEntityId())) {
				builder.entityId(basePath);
			}
			if (!hasText(registration.getAlias())) {
				builder.alias(request.getServerName());
			}
			if (!hasText(registration.getBasePath())) {
				builder.basePath(basePath);
			}
		}
		return builder.build();
	}

	@Override
	public String getHttpPathPrefix() {
		return registration.getPathPrefix();
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
