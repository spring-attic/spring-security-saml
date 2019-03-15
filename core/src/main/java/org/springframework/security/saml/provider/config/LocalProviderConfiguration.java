/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.provider.config;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static org.springframework.util.StringUtils.hasText;

public class LocalProviderConfiguration<
	LocalConfiguration extends LocalProviderConfiguration,
	ExternalConfiguration extends ExternalProviderConfiguration<ExternalConfiguration>> implements Cloneable {

	private String entityId;
	private String alias;
	private boolean signMetadata;
	private String metadata;
	private RotatingKeys keys;
	private String prefix;
	private boolean singleLogoutEnabled = true;
	private List<NameId> nameIds = new LinkedList<>();
	private AlgorithmMethod defaultSigningAlgorithm = AlgorithmMethod.RSA_SHA256;
	private DigestMethod defaultDigest = DigestMethod.SHA256;
	private List<ExternalConfiguration> providers = new LinkedList<>();
	private String basePath;


	public LocalProviderConfiguration(String prefix) {
		setPrefix(prefix);
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

	@SuppressWarnings("checked")
	protected LocalConfiguration _this() {
		return (LocalConfiguration) this;
	}

	public String getEntityId() {
		return entityId;
	}

	public LocalConfiguration setEntityId(String entityId) {
		this.entityId = entityId;
		return _this();
	}

	public boolean isSignMetadata() {
		return signMetadata;
	}

	public LocalConfiguration setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
		return _this();
	}

	public String getMetadata() {
		return metadata;
	}

	public LocalConfiguration setMetadata(String metadata) {
		this.metadata = metadata;
		return _this();
	}

	public RotatingKeys getKeys() {
		return keys;
	}

	public LocalConfiguration setKeys(RotatingKeys keys) {
		this.keys = keys;
		return _this();
	}

	public String getAlias() {
		return alias;
	}

	public LocalConfiguration setAlias(String alias) {
		this.alias = alias;
		return _this();
	}

	public String getPrefix() {
		return prefix;
	}

	public LocalConfiguration setPrefix(String prefix) {
		prefix = cleanPrefix(prefix);
		this.prefix = prefix;

		return _this();
	}

	public boolean isSingleLogoutEnabled() {
		return singleLogoutEnabled;
	}

	public LocalConfiguration setSingleLogoutEnabled(boolean singleLogoutEnabled) {
		this.singleLogoutEnabled = singleLogoutEnabled;
		return _this();
	}

	public List<NameId> getNameIds() {
		return nameIds;
	}

	public LocalConfiguration setNameIds(List<Object> nameIds) {
		this.nameIds = nameIds.stream().map(
			n -> n instanceof String ? NameId.fromUrn((String)n) : (NameId)n).collect(Collectors.toList()
		);
		return _this();
	}

	public AlgorithmMethod getDefaultSigningAlgorithm() {
		return defaultSigningAlgorithm;
	}

	public LocalConfiguration setDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
		this.defaultSigningAlgorithm = defaultSigningAlgorithm;
		return _this();
	}

	public DigestMethod getDefaultDigest() {
		return defaultDigest;
	}

	public LocalConfiguration setDefaultDigest(DigestMethod defaultDigest) {
		this.defaultDigest = defaultDigest;
		return _this();
	}

	public String getBasePath() {
		return basePath;
	}

	public LocalProviderConfiguration<LocalConfiguration, ExternalConfiguration> setBasePath(String basePath) {
		this.basePath = basePath;
		return this;
	}

	@Override
	public LocalConfiguration clone() throws CloneNotSupportedException {
		LocalConfiguration result = (LocalConfiguration) super.clone();
		LinkedList<ExternalConfiguration> newProviders = new LinkedList<>();
		for (ExternalConfiguration externalConfiguration : getProviders()) {
			newProviders.add(externalConfiguration.clone());
		}
		result.setProviders(newProviders);
		return result;
	}

	public List<ExternalConfiguration> getProviders() {
		return providers;
	}

	public LocalConfiguration setProviders(List<ExternalConfiguration> providers) {
		this.providers = providers;
		return _this();
	}
}
