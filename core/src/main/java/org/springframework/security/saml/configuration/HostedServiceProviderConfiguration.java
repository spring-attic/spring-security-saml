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

import java.util.List;

import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static java.util.Arrays.asList;

/**
 * Immutable configuration object that represents a local service provider (SP) service.
 */
public class HostedServiceProviderConfiguration extends
	HostedProviderConfiguration<ExternalIdentityProviderConfiguration> {

	private final boolean signRequests;
	private final boolean wantAssertionsSigned;

	public HostedServiceProviderConfiguration(String pathPrefix,
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
											  List<ExternalIdentityProviderConfiguration> providers,
											  boolean signRequests,
											  boolean wantAssertionsSigned) {
		super(
			pathPrefix,
			basePath,
			alias,
			entityId,
			signMetadata,
			metadata,
			keys,
			defaultSigningAlgorithm,
			defaultDigest,
			nameIds,
			singleLogoutEnabled,
			providers
		);
		this.signRequests = signRequests;
		this.wantAssertionsSigned = wantAssertionsSigned;
	}

	public boolean isSignRequests() {
		return signRequests;
	}

	public boolean isWantAssertionsSigned() {
		return wantAssertionsSigned;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder builder(HostedServiceProviderConfiguration configuration) {
		return builder()
			.signRequests(configuration.isSignRequests())
			.wantAssertionsSigned(configuration.isWantAssertionsSigned())
			.pathPrefix(configuration.getPathPrefix())
			.basePath(configuration.getBasePath())
			.alias(configuration.getAlias())
			.entityId(configuration.getEntityId())
			.signMetadata(configuration.isSignMetadata())
			.metadata(configuration.getMetadata())
			.keys(configuration.getKeys())
			.defaultSigningAlgorithm(configuration.getDefaultSigningAlgorithm())
			.defaultDigest(configuration.getDefaultDigest())
			.nameIds(configuration.getNameIds())
			.singleLogoutEnabled(configuration.isSingleLogoutEnabled())
			.providers(configuration.getProviders());
	}

	public static final class Builder {
		private boolean signRequests = true;
		private boolean wantAssertionsSigned = true;
		private String pathPrefix = "/saml/sp";
		private String basePath;
		private String alias;
		private String entityId;
		private boolean signMetadata = true;
		private String metadata;
		private List<KeyData> keys;
		private AlgorithmMethod defaultSigningAlgorithm = AlgorithmMethod.RSA_SHA256;
		private DigestMethod defaultDigest = DigestMethod.SHA256;
		private List<NameId> nameIds = asList(NameId.PERSISTENT, NameId.EMAIL);
		private boolean singleLogoutEnabled = true;
		private List<ExternalIdentityProviderConfiguration> providers;

		private Builder() {
		}

		public Builder signRequests(boolean signRequests) {
			this.signRequests = signRequests;
			return this;
		}

		public Builder wantAssertionsSigned(boolean wantAssertionsSigned) {
			this.wantAssertionsSigned = wantAssertionsSigned;
			return this;
		}

		public Builder pathPrefix(String pathPrefix) {
			this.pathPrefix = pathPrefix;
			return this;
		}

		public Builder basePath(String basePath) {
			this.basePath = basePath;
			return this;
		}

		public Builder alias(String alias) {
			this.alias = alias;
			return this;
		}

		public Builder entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		public Builder signMetadata(boolean signMetadata) {
			this.signMetadata = signMetadata;
			return this;
		}

		public Builder metadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public Builder keys(List<KeyData> keys) {
			this.keys = keys;
			return this;
		}

		public Builder keys(KeyData... keys) {
			this.keys = asList(keys);
			return this;
		}

		public Builder defaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
			this.defaultSigningAlgorithm = defaultSigningAlgorithm;
			return this;
		}

		public Builder defaultDigest(DigestMethod defaultDigest) {
			this.defaultDigest = defaultDigest;
			return this;
		}

		public Builder nameIds(List<NameId> nameIds) {
			this.nameIds = nameIds;
			return this;
		}

		public Builder singleLogoutEnabled(boolean singleLogoutEnabled) {
			this.singleLogoutEnabled = singleLogoutEnabled;
			return this;
		}

		public Builder providers(List<ExternalIdentityProviderConfiguration> providers) {
			this.providers = providers;
			return this;
		}

		public Builder providers(ExternalIdentityProviderConfiguration... providers) {
			this.providers = asList(providers);
			return this;
		}

		public HostedServiceProviderConfiguration build() {
			HostedServiceProviderConfiguration hostedServiceProviderConfiguration =
				new HostedServiceProviderConfiguration(
					pathPrefix,
					basePath,
					alias,
					entityId,
					signMetadata,
					metadata,
					keys,
					defaultSigningAlgorithm,
					defaultDigest,
					nameIds,
					singleLogoutEnabled,
					providers,
					signRequests,
					wantAssertionsSigned);
			return hostedServiceProviderConfiguration;
		}
	}
}
