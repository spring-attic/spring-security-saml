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

package org.springframework.security.saml2.provider;

import java.util.Map;

import org.springframework.security.saml2.model.metadata.Saml2Metadata;
import org.springframework.security.saml2.registration.ExternalSaml2ProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2ProviderRegistration;

/**
 * Represents a hosted provider, either Service Provider or Identity Provider
 * @param <Registration>       - the local configuration type for this provider
 * @param <LocalMetadata>      - the generated metadata for this provider
 * @param <RemoteRegistration> - the configuration type of a remote paired provider
 * @param <RemoteMetadata>     - the metadata of the remote provider
 */
public interface Saml2ProviderInstance<
	Registration extends HostedSaml2ProviderRegistration,
	LocalMetadata extends Saml2Metadata,
	RemoteRegistration extends ExternalSaml2ProviderRegistration,
	RemoteMetadata extends Saml2Metadata> {

	Registration getRegistration();

	LocalMetadata getMetadata();

	Map<RemoteRegistration,RemoteMetadata> getRemoteProviders();

	RemoteMetadata getRemoteProvider(String entityId);
}
