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

import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static java.util.Arrays.asList;

/**
 * Immutable configuration object that represents a local identity provider (IDP) service.
 */
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

	public static Builder builder() {
		return new Builder();
	}

	public static Builder builder(HostedIdentityProviderConfiguration configuration) {
		return builder()
			.wantRequestsSigned(configuration.isWantRequestsSigned())
			.signAssertions(configuration.isSignAssertions())
			.encryptAssertions(configuration.isEncryptAssertions())
			.keyEncryptionAlgorithm(configuration.getKeyEncryptionAlgorithm())
			.dataEncryptionAlgorithm(configuration.getDataEncryptionAlgorithm())
			.notOnOrAfter(configuration.getNotOnOrAfter())
			.notBefore(configuration.getNotBefore())
			.sessionNotOnOrAfter(configuration.getSessionNotOnOrAfter())
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

		public Builder pathPrefix(String pathPrefix) {
			this.pathPrefix = pathPrefix;
			return this;
		}

		public Builder basePath(String basePath) {
			this.basePath = basePath;
			return this;
		}

		public Builder wantRequestsSigned(boolean wantRequestsSigned) {
			this.wantRequestsSigned = wantRequestsSigned;
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

		public Builder signAssertions(boolean signAssertions) {
			this.signAssertions = signAssertions;
			return this;
		}

		public Builder signMetadata(boolean signMetadata) {
			this.signMetadata = signMetadata;
			return this;
		}

		public Builder encryptAssertions(boolean encryptAssertions) {
			this.encryptAssertions = encryptAssertions;
			return this;
		}

		public Builder metadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public Builder keyEncryptionAlgorithm(KeyEncryptionMethod keyEncryptionAlgorithm) {
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			return this;
		}

		public Builder keys(List<KeyData> keys) {
			this.keys = keys;
			return this;
		}

		public Builder defaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
			this.defaultSigningAlgorithm = defaultSigningAlgorithm;
			return this;
		}

		public Builder dataEncryptionAlgorithm(DataEncryptionMethod dataEncryptionAlgorithm) {
			this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
			return this;
		}

		public Builder defaultDigest(DigestMethod defaultDigest) {
			this.defaultDigest = defaultDigest;
			return this;
		}

		public Builder notOnOrAfter(long notOnOrAfter) {
			this.notOnOrAfter = notOnOrAfter;
			return this;
		}

		public Builder notBefore(long notBefore) {
			this.notBefore = notBefore;
			return this;
		}

		public Builder nameIds(List<NameId> nameIds) {
			this.nameIds = nameIds;
			return this;
		}

		public Builder nameIds(NameId... nameIds) {
			this.nameIds = asList(nameIds);
			return this;
		}

		public Builder sessionNotOnOrAfter(long sessionNotOnOrAfter) {
			this.sessionNotOnOrAfter = sessionNotOnOrAfter;
			return this;
		}

		public Builder singleLogoutEnabled(boolean singleLogoutEnabled) {
			this.singleLogoutEnabled = singleLogoutEnabled;
			return this;
		}

		public Builder providers(List<ExternalServiceProviderConfiguration> providers) {
			this.providers = providers;
			return this;
		}

		public Builder providers(ExternalServiceProviderConfiguration... providers) {
			this.providers = asList(providers);
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
