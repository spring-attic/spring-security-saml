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

package org.springframework.security.saml.configuration;

import java.util.Collections;
import java.util.List;

import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

public abstract class HostedProviderConfiguration
	<ExternalConfiguration extends ExternalProviderConfiguration<ExternalConfiguration>> {

	private final String pathPrefix;
	private final String basePath;
	private final String alias;
	private final String entityId;
	private final boolean signMetadata;
	private final String metadata;
	private final List<KeyData> keys;
	private final AlgorithmMethod defaultSigningAlgorithm;
	private final DigestMethod defaultDigest;
	private final List<NameId> nameIds;
	private final boolean singleLogoutEnabled;
	private final List<ExternalConfiguration> providers;

	HostedProviderConfiguration(String pathPrefix,
								String basePath,
								String alias,
								String entityId,
								boolean signMetadata,
								String metadata,
								List<KeyData> keys,
								AlgorithmMethod defaultSigningAlgorithm,
								DigestMethod defaultDigest,
								List<NameId> nameIds,
								boolean singleLogoutEnabled,
								List<ExternalConfiguration> providers) {
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

	public List<KeyData> getKeys() {
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

	public List<NameId> getNameIds() {
		return nameIds;
	}

	public AlgorithmMethod getDefaultSigningAlgorithm() {
		return defaultSigningAlgorithm;
	}

	public DigestMethod getDefaultDigest() {
		return defaultDigest;
	}

	public String getBasePath() {
		return basePath;
	}

	public List<ExternalConfiguration> getProviders() {
		return providers;
	}


}
