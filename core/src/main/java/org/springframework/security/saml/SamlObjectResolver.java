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

package org.springframework.security.saml;

import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

public interface SamlObjectResolver {

	ServiceProviderMetadata getLocalServiceProvider(String baseUrl);

	IdentityProviderMetadata getLocalIdentityProvider(String baseUrl);

	IdentityProviderMetadata resolveIdentityProvider(Assertion assertion);

	IdentityProviderMetadata resolveIdentityProvider(Response response);

	IdentityProviderMetadata resolveIdentityProvider(String entityId);

	IdentityProviderMetadata resolveIdentityProvider(ExternalProviderConfiguration idp);

	IdentityProviderMetadata resolveIdentityProvider(LogoutRequest logoutRequest);

	ServiceProviderMetadata resolveServiceProvider(String entityId);

	ServiceProviderMetadata resolveServiceProvider(AuthenticationRequest request);

	ServiceProviderMetadata resolveServiceProvider(ExternalProviderConfiguration sp);

	ServiceProviderMetadata resolveServiceProvider(LogoutRequest logoutRequest);
}
