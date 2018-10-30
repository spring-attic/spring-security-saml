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

package org.springframework.security.saml.registration;

import java.util.List;

import org.springframework.security.saml.saml2.key.SimpleKey;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

public class HostedServiceProviderConfiguration extends
	HostedProviderConfiguration<ExternalIdentityProviderConfiguration> {

	private final boolean signRequests;
	private final boolean wantAssertionsSigned;

	public HostedServiceProviderConfiguration(String prefix,
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
											  List<ExternalIdentityProviderConfiguration> providers,
											  boolean signRequests,
											  boolean wantAssertionsSigned) {
		super(
			prefix,
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


	public static final class Builder {
		private boolean signRequests;
		private boolean wantAssertionsSigned;
		private String prefix;
		private String basePath;
		private String alias;
		private String entityId;
		private boolean signMetadata;
		private String metadata;
		private List<SimpleKey> keys;
		private AlgorithmMethod defaultSigningAlgorithm;
		private DigestMethod defaultDigest;
		private List<NameId> nameIds;
		private boolean singleLogoutEnabled;
		private List<ExternalIdentityProviderConfiguration> providers;

		private Builder() {
		}

		public static Builder builder() {
			return new Builder();
		}

		public static Builder builder(HostedServiceProviderConfiguration configuration) {
			return builder()
				.withSignRequests(configuration.isSignRequests())
				.withWantAssertionsSigned(configuration.isWantAssertionsSigned())
				.withPrefix(configuration.getPrefix())
				.withBasePath(configuration.getBasePath())
				.withAlias(configuration.getAlias())
				.withEntityId(configuration.getEntityId())
				.withSignMetadata(configuration.isSignMetadata())
				.withMetadata(configuration.getMetadata())
				.withKeys(configuration.getKeys())
				.withDefaultSigningAlgorithm(configuration.getDefaultSigningAlgorithm())
				.withDefaultDigest(configuration.getDefaultDigest())
				.withNameIds(configuration.getNameIds())
				.withSingleLogoutEnabled(configuration.isSingleLogoutEnabled())
				.withProviders(configuration.getProviders());
		}

		public Builder withSignRequests(boolean signRequests) {
			this.signRequests = signRequests;
			return this;
		}

		public Builder withWantAssertionsSigned(boolean wantAssertionsSigned) {
			this.wantAssertionsSigned = wantAssertionsSigned;
			return this;
		}

		public Builder withPrefix(String prefix) {
			this.prefix = prefix;
			return this;
		}

		public Builder withBasePath(String basePath) {
			this.basePath = basePath;
			return this;
		}

		public Builder withAlias(String alias) {
			this.alias = alias;
			return this;
		}

		public Builder withEntityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		public Builder withSignMetadata(boolean signMetadata) {
			this.signMetadata = signMetadata;
			return this;
		}

		public Builder withMetadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public Builder withKeys(List<SimpleKey> keys) {
			this.keys = keys;
			return this;
		}

		public Builder withDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
			this.defaultSigningAlgorithm = defaultSigningAlgorithm;
			return this;
		}

		public Builder withDefaultDigest(DigestMethod defaultDigest) {
			this.defaultDigest = defaultDigest;
			return this;
		}

		public Builder withNameIds(List<NameId> nameIds) {
			this.nameIds = nameIds;
			return this;
		}

		public Builder withSingleLogoutEnabled(boolean singleLogoutEnabled) {
			this.singleLogoutEnabled = singleLogoutEnabled;
			return this;
		}

		public Builder withProviders(List<ExternalIdentityProviderConfiguration> providers) {
			this.providers = providers;
			return this;
		}

		public HostedServiceProviderConfiguration build() {
			HostedServiceProviderConfiguration hostedServiceProviderConfiguration =
				new HostedServiceProviderConfiguration(prefix,
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