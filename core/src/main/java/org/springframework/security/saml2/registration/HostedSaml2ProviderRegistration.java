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

package org.springframework.security.saml2.registration;

import java.util.Collections;
import java.util.List;

import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;

/**
 * Base class for a SAML2 local provider. A local provider can be paired up with one or more
 * external SAML2 providers
 *
 * @param <ExternalRegistration> either a {@link ExternalSaml2IdentityProviderRegistration} or
 *                               {@link ExternalSaml2ServiceProviderRegistration}
 */
public abstract class HostedSaml2ProviderRegistration
	<ExternalRegistration extends ExternalSaml2ProviderRegistration<ExternalRegistration>> {

	private final String pathPrefix;
	private final String basePath;
	private final String alias;
	private final String entityId;
	private final boolean signMetadata;
	private final String metadata;
	private final List<Saml2KeyData> keys;
	private final Saml2AlgorithmMethod defaultSigningAlgorithm;
	private final Saml2DigestMethod defaultDigest;
	private final List<Saml2NameId> nameIds;
	private final boolean singleLogoutEnabled;
	private final List<ExternalRegistration> providers;

	HostedSaml2ProviderRegistration(String pathPrefix,
									String basePath,
									String alias,
									String entityId,
									boolean signMetadata,
									String metadata,
									List<Saml2KeyData> keys,
									Saml2AlgorithmMethod defaultSigningAlgorithm,
									Saml2DigestMethod defaultDigest,
									List<Saml2NameId> nameIds,
									boolean singleLogoutEnabled,
									List<ExternalRegistration> providers) {
		this.pathPrefix = pathPrefix;
		this.basePath = basePath;
		this.alias = alias;
		this.entityId = entityId;
		this.signMetadata = signMetadata;
		this.metadata = metadata;
		this.keys = Collections.unmodifiableList(keys);
		this.defaultSigningAlgorithm = defaultSigningAlgorithm;
		this.defaultDigest = defaultDigest;
		this.nameIds = nameIds;
		this.singleLogoutEnabled = singleLogoutEnabled;
		this.providers = Collections.unmodifiableList(providers);
	}

	public String getEntityId() {
		return entityId;
	}

	public boolean isSignMetadata() {
		return signMetadata;
	}

	public String getMetadata() {
		return metadata;
	}

	public List<Saml2KeyData> getKeys() {
		return keys;
	}

	public String getAlias() {
		return alias;
	}

	public String getPathPrefix() {
		return pathPrefix;
	}

	public boolean isSingleLogoutEnabled() {
		return singleLogoutEnabled;
	}

	public List<Saml2NameId> getNameIds() {
		return nameIds;
	}

	public Saml2AlgorithmMethod getDefaultSigningAlgorithm() {
		return defaultSigningAlgorithm;
	}

	public Saml2DigestMethod getDefaultDigest() {
		return defaultDigest;
	}

	public String getBasePath() {
		return basePath;
	}

	public List<ExternalRegistration> getProviders() {
		return providers;
	}


}
