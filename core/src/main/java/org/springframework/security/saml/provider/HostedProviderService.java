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

package org.springframework.security.saml.provider;

import java.util.List;

import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.config.HostedProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.validation.ValidationResult;

public interface HostedProviderService<
	Configuration extends HostedProviderConfiguration,
	LocalMetadata extends Metadata,
	RemoteMetadata extends Metadata> {

	Configuration getConfiguration();

	LocalMetadata getMetadata();

	List<RemoteMetadata> getRemoteProviders();

	LogoutRequest logoutRequest(RemoteMetadata recipient,
								NameIdPrincipal principal);

	LogoutResponse logoutResponse(LogoutRequest request,
								  RemoteMetadata recipient);

	RemoteMetadata getRemoteProvider(Saml2Object saml2Object);

	RemoteMetadata getRemoteProvider(String entityId);

	RemoteMetadata getRemoteProvider(ExternalProviderConfiguration c);

	ValidationResult validate(Saml2Object saml2Object);

	<T extends Saml2Object> T fromXml(String xml, boolean encoded, boolean deflated, Class<T> type);

	String toXml(Saml2Object saml2Object);

	String toEncodedXml(Saml2Object saml2Object, boolean deflate);

	String toEncodedXml(String xml, boolean deflate);

	Endpoint getPreferredEndpoint(List<Endpoint> endpoints,
								  Binding preferredBinding,
								  int preferredIndex);

}
