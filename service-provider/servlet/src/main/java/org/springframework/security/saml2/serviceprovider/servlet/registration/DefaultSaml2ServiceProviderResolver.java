/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml2.serviceprovider.servlet.registration;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration;
import org.springframework.security.saml2.provider.Saml2ServiceProviderInstance;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderRegistrationResolver;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.metadata.Saml2ServiceProviderMetadataResolver;

public class DefaultSaml2ServiceProviderResolver implements Saml2ServiceProviderResolver<HttpServletRequest> {

	private final Saml2ServiceProviderMetadataResolver metadataResolver;
	private final Saml2ServiceProviderRegistrationResolver configResolver;

	public DefaultSaml2ServiceProviderResolver(Saml2ServiceProviderMetadataResolver metadataResolver,
											   Saml2ServiceProviderRegistrationResolver configResolver) {
		this.configResolver = configResolver;
		this.metadataResolver = metadataResolver;
	}

	@Override
	public Saml2ServiceProviderInstance getServiceProvider(HttpServletRequest request) {
		HostedSaml2ServiceProviderRegistration config = configResolver.getServiceProviderRegistration(request);
		return new Saml2ServiceProviderInstance(
			config,
			metadataResolver.getMetadata(config),
			metadataResolver.getIdentityProviders(config)
		);
	}

	@Override
	public String getHttpPathPrefix() {
		return configResolver.getHttpPathPrefix();
	}
}
