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

package org.springframework.security.saml.boot.configuration;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public abstract class LocalProviderConfiguration
	<ExternalConfiguration extends RemoteProviderConfiguration> {

	private String entityId;
	private String alias;
	private boolean signMetadata;
	private String metadata;
	@NestedConfigurationProperty
	private RotatingKeys keys = new RotatingKeys();
	private String pathPrefix;
	private boolean singleLogoutEnabled = true;
	@NestedConfigurationProperty
	private List<NameId> nameIds = new LinkedList<>();
	private AlgorithmMethod defaultSigningAlgorithm = AlgorithmMethod.RSA_SHA256;
	private DigestMethod defaultDigest = DigestMethod.SHA256;
	@NestedConfigurationProperty
	private List<ExternalConfiguration> providers = new LinkedList<>();
	private String basePath;


	public LocalProviderConfiguration(String pathPrefix) {
		setPathPrefix(pathPrefix);
	}

	public String getEntityId() {
		return entityId;
	}

	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public boolean isSignMetadata() {
		return signMetadata;
	}

	public void setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
	}

	public String getMetadata() {
		return metadata;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public RotatingKeys getKeys() {
		return keys;
	}

	public void setKeys(RotatingKeys keys) {
		this.keys = keys;
	}

	public String getPathPrefix() {
		return pathPrefix;
	}

	public void setPathPrefix(String pathPrefix) {
		this.pathPrefix = stripSlashes(pathPrefix);
	}

	public boolean isSingleLogoutEnabled() {
		return singleLogoutEnabled;
	}

	public void setSingleLogoutEnabled(boolean singleLogoutEnabled) {
		this.singleLogoutEnabled = singleLogoutEnabled;
	}

	public List<NameId> getNameIds() {
		return nameIds;
	}

	public void setNameIds(List<Object> nameIds) {
		this.nameIds = nameIds.stream().map(
			n -> (n instanceof String) ? NameId.fromUrn((String)n) : (NameId)n
		)
			.collect(Collectors.toList());
	}

	public AlgorithmMethod getDefaultSigningAlgorithm() {
		return defaultSigningAlgorithm;
	}

	public void setDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
		this.defaultSigningAlgorithm = defaultSigningAlgorithm;
	}

	public DigestMethod getDefaultDigest() {
		return defaultDigest;
	}

	public void setDefaultDigest(DigestMethod defaultDigest) {
		this.defaultDigest = defaultDigest;
	}

	public List<ExternalConfiguration> getProviders() {
		return providers;
	}

	public void setProviders(List<ExternalConfiguration> providers) {
		this.providers = providers;
	}

	public String getBasePath() {
		return basePath;
	}

	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}
}
