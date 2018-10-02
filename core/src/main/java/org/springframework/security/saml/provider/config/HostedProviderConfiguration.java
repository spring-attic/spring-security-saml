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

package org.springframework.security.saml.provider.config;

import java.util.Collections;
import java.util.List;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static org.springframework.util.StringUtils.hasText;

public class HostedProviderConfiguration
	<ExternalConfiguration extends ExternalProviderConfiguration<ExternalConfiguration>> {

	private final String prefix;
	private final String basePath;
	private final String alias;
	private final String entityId;
	private final boolean signMetadata;
	private final String metadata;
	private final List<SimpleKey> keys;
	private final AlgorithmMethod defaultSigningAlgorithm;
	private final DigestMethod defaultDigest;
	private final List<NameId> nameIds;
	private final boolean singleLogoutEnabled;
	private final List<ExternalConfiguration> providers;

	public HostedProviderConfiguration(String prefix,
									   String basePath,
									   String alias,
									   String entityId,
									   boolean signMetadata,
									   String metadata,
									   List<SimpleKey> keys,
									   AlgorithmMethod defaultSigningAlgorithm,
									   DigestMethod defaultDigest,
									   List<NameId> nameIds,
									   boolean singleLogoutEnabled,
									   List<ExternalConfiguration> providers) {
		this.prefix = prefix;
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


	protected String cleanPrefix(String prefix) {
		if (hasText(prefix) && prefix.startsWith("/")) {
			prefix = prefix.substring(1);
		}
		if (hasText(prefix) && !prefix.endsWith("/")) {
			prefix = prefix + "/";
		}
		return prefix;
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

	public List<SimpleKey> getKeys() {
		return keys;
	}

	public String getAlias() {
		return alias;
	}

	public String getPrefix() {
		return prefix;
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
