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

import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

public class HostedIdentityProviderConfiguration extends
	HostedProviderConfiguration<ExternalServiceProviderConfiguration> {

	private final boolean wantRequestsSigned;
	private final boolean signAssertions;
	private final boolean encryptAssertions;
	private final KeyEncryptionMethod keyEncryptionAlgorithm;
	private final DataEncryptionMethod dataEncryptionAlgorithm;
	private final long notOnOrAfter;
	private final long notBefore;
	private final long sessionNotOnOrAfter;

	public HostedIdentityProviderConfiguration(String pathPrefix,
											   String basePath,
											   String alias,
											   String entityId,
											   boolean signMetadata,
											   boolean signAssertions,
											   boolean wantRequestsSigned,
											   String metadata,
											   List<KeyData> keys,
											   AlgorithmMethod defaultSigningAlgorithm,
											   DigestMethod defaultDigest,
											   List<NameId> nameIds,
											   boolean singleLogoutEnabled,
											   List<ExternalServiceProviderConfiguration> providers,
											   boolean encryptAssertions,
											   KeyEncryptionMethod keyEncryptionAlgorithm,
											   DataEncryptionMethod dataEncryptionAlgorithm,
											   long notOnOrAfter,
											   long notBefore,
											   long sessionNotOnOrAfter) {
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
		this.wantRequestsSigned = wantRequestsSigned;
		this.signAssertions = signAssertions;
		this.encryptAssertions = encryptAssertions;
		this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
		this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
		this.notOnOrAfter = notOnOrAfter;
		this.notBefore = notBefore;
		this.sessionNotOnOrAfter = sessionNotOnOrAfter;
	}

	public boolean isWantRequestsSigned() {
		return wantRequestsSigned;
	}

	public boolean isSignAssertions() {
		return signAssertions;
	}

	public long getNotOnOrAfter() {
		return notOnOrAfter;
	}

	public long getNotBefore() {
		return notBefore;
	}

	public long getSessionNotOnOrAfter() {
		return sessionNotOnOrAfter;
	}

	public boolean isEncryptAssertions() {
		return encryptAssertions;
	}

	public KeyEncryptionMethod getKeyEncryptionAlgorithm() {
		return keyEncryptionAlgorithm;
	}

	public DataEncryptionMethod getDataEncryptionAlgorithm() {
		return dataEncryptionAlgorithm;
	}


	public static final class Builder {
		private String pathPrefix;
		private String basePath;
		private boolean wantRequestsSigned;
		private String alias;
		private String entityId;
		private boolean signAssertions;
		private boolean signMetadata;
		private boolean encryptAssertions;
		private String metadata;
		private KeyEncryptionMethod keyEncryptionAlgorithm;
		private List<KeyData> keys;
		private AlgorithmMethod defaultSigningAlgorithm;
		private DataEncryptionMethod dataEncryptionAlgorithm;
		private DigestMethod defaultDigest;
		private long notOnOrAfter;
		private long notBefore;
		private List<NameId> nameIds;
		private long sessionNotOnOrAfter;
		private boolean singleLogoutEnabled;
		private List<ExternalServiceProviderConfiguration> providers;

		private Builder() {
		}

		public static Builder builder() {
			return new Builder();
		}

		public static Builder builder(HostedIdentityProviderConfiguration configuration) {
			return builder()
				.withWantRequestsSigned(configuration.isWantRequestsSigned())
				.withSignAssertions(configuration.isSignAssertions())
				.withEncryptAssertions(configuration.isEncryptAssertions())
				.withKeyEncryptionAlgorithm(configuration.getKeyEncryptionAlgorithm())
				.withDataEncryptionAlgorithm(configuration.getDataEncryptionAlgorithm())
				.withNotOnOrAfter(configuration.getNotOnOrAfter())
				.withNotBefore(configuration.getNotBefore())
				.withSessionNotOnOrAfter(configuration.getSessionNotOnOrAfter())
				.withPathPrefix(configuration.getPathPrefix())
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

		public Builder withPathPrefix(String pathPrefix) {
			this.pathPrefix = pathPrefix;
			return this;
		}

		public Builder withBasePath(String basePath) {
			this.basePath = basePath;
			return this;
		}

		public Builder withWantRequestsSigned(boolean wantRequestsSigned) {
			this.wantRequestsSigned = wantRequestsSigned;
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

		public Builder withSignAssertions(boolean signAssertions) {
			this.signAssertions = signAssertions;
			return this;
		}

		public Builder withSignMetadata(boolean signMetadata) {
			this.signMetadata = signMetadata;
			return this;
		}

		public Builder withEncryptAssertions(boolean encryptAssertions) {
			this.encryptAssertions = encryptAssertions;
			return this;
		}

		public Builder withMetadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public Builder withKeyEncryptionAlgorithm(KeyEncryptionMethod keyEncryptionAlgorithm) {
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			return this;
		}

		public Builder withKeys(List<KeyData> keys) {
			this.keys = keys;
			return this;
		}

		public Builder withDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
			this.defaultSigningAlgorithm = defaultSigningAlgorithm;
			return this;
		}

		public Builder withDataEncryptionAlgorithm(DataEncryptionMethod dataEncryptionAlgorithm) {
			this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
			return this;
		}

		public Builder withDefaultDigest(DigestMethod defaultDigest) {
			this.defaultDigest = defaultDigest;
			return this;
		}

		public Builder withNotOnOrAfter(long notOnOrAfter) {
			this.notOnOrAfter = notOnOrAfter;
			return this;
		}

		public Builder withNotBefore(long notBefore) {
			this.notBefore = notBefore;
			return this;
		}

		public Builder withNameIds(List<NameId> nameIds) {
			this.nameIds = nameIds;
			return this;
		}

		public Builder withSessionNotOnOrAfter(long sessionNotOnOrAfter) {
			this.sessionNotOnOrAfter = sessionNotOnOrAfter;
			return this;
		}

		public Builder withSingleLogoutEnabled(boolean singleLogoutEnabled) {
			this.singleLogoutEnabled = singleLogoutEnabled;
			return this;
		}

		public Builder withProviders(List<ExternalServiceProviderConfiguration> providers) {
			this.providers = providers;
			return this;
		}

		public HostedIdentityProviderConfiguration build() {
			HostedIdentityProviderConfiguration hostedIdentityProviderConfiguration =
				new HostedIdentityProviderConfiguration(
					pathPrefix,
					basePath,
					alias,
					entityId,
					signMetadata,
					signAssertions,
					wantRequestsSigned,
					metadata,
					keys,
					defaultSigningAlgorithm,
					defaultDigest,
					nameIds,
					singleLogoutEnabled,
					providers,
					encryptAssertions,
					keyEncryptionAlgorithm,
					dataEncryptionAlgorithm,
					notOnOrAfter,
					notBefore,
					sessionNotOnOrAfter
				);
			return hostedIdentityProviderConfiguration;
		}
	}
}
