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

import java.util.List;

import org.springframework.security.saml2.model.encrypt.Saml2DataEncryptionMethod;
import org.springframework.security.saml2.model.encrypt.Saml2KeyEncryptionMethod;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;

import static java.util.Arrays.asList;

/**
 * Immutable configuration object that represents a local identity provider (IDP) service.
 */
public class HostedSaml2IdentityProviderRegistration extends
	HostedSaml2ProviderRegistration<ExternalSaml2ServiceProviderRegistration> {

	private final boolean wantRequestsSigned;
	private final boolean signAssertions;
	private final boolean encryptAssertions;
	private final Saml2KeyEncryptionMethod keyEncryptionAlgorithm;
	private final Saml2DataEncryptionMethod dataEncryptionAlgorithm;
	private final long notOnOrAfter;
	private final long notBefore;
	private final long sessionNotOnOrAfter;

	public HostedSaml2IdentityProviderRegistration(String pathPrefix,
												   String basePath,
												   String alias,
												   String entityId,
												   boolean signMetadata,
												   boolean signAssertions,
												   boolean wantRequestsSigned,
												   String metadata,
												   List<Saml2KeyData> keys,
												   Saml2AlgorithmMethod defaultSigningAlgorithm,
												   Saml2DigestMethod defaultDigest,
												   List<Saml2NameId> nameIds,
												   boolean singleLogoutEnabled,
												   List<ExternalSaml2ServiceProviderRegistration> providers,
												   boolean encryptAssertions,
												   Saml2KeyEncryptionMethod keyEncryptionAlgorithm,
												   Saml2DataEncryptionMethod dataEncryptionAlgorithm,
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

	public Saml2KeyEncryptionMethod getKeyEncryptionAlgorithm() {
		return keyEncryptionAlgorithm;
	}

	public Saml2DataEncryptionMethod getDataEncryptionAlgorithm() {
		return dataEncryptionAlgorithm;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder builder(HostedSaml2IdentityProviderRegistration registration) {
		return builder()
			.wantRequestsSigned(registration.isWantRequestsSigned())
			.signAssertions(registration.isSignAssertions())
			.encryptAssertions(registration.isEncryptAssertions())
			.keyEncryptionAlgorithm(registration.getKeyEncryptionAlgorithm())
			.dataEncryptionAlgorithm(registration.getDataEncryptionAlgorithm())
			.notOnOrAfter(registration.getNotOnOrAfter())
			.notBefore(registration.getNotBefore())
			.sessionNotOnOrAfter(registration.getSessionNotOnOrAfter())
			.pathPrefix(registration.getPathPrefix())
			.basePath(registration.getBasePath())
			.alias(registration.getAlias())
			.entityId(registration.getEntityId())
			.signMetadata(registration.isSignMetadata())
			.metadata(registration.getMetadata())
			.keys(registration.getKeys())
			.defaultSigningAlgorithm(registration.getDefaultSigningAlgorithm())
			.defaultDigest(registration.getDefaultDigest())
			.nameIds(registration.getNameIds())
			.singleLogoutEnabled(registration.isSingleLogoutEnabled())
			.providers(registration.getProviders());
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
		private Saml2KeyEncryptionMethod keyEncryptionAlgorithm;
		private List<Saml2KeyData> keys;
		private Saml2AlgorithmMethod defaultSigningAlgorithm;
		private Saml2DataEncryptionMethod dataEncryptionAlgorithm;
		private Saml2DigestMethod defaultDigest;
		private long notOnOrAfter;
		private long notBefore;
		private List<Saml2NameId> nameIds;
		private long sessionNotOnOrAfter;
		private boolean singleLogoutEnabled;
		private List<ExternalSaml2ServiceProviderRegistration> providers;

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

		public Builder keyEncryptionAlgorithm(Saml2KeyEncryptionMethod keyEncryptionAlgorithm) {
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			return this;
		}

		public Builder keys(List<Saml2KeyData> keys) {
			this.keys = keys;
			return this;
		}

		public Builder defaultSigningAlgorithm(Saml2AlgorithmMethod defaultSigningAlgorithm) {
			this.defaultSigningAlgorithm = defaultSigningAlgorithm;
			return this;
		}

		public Builder dataEncryptionAlgorithm(Saml2DataEncryptionMethod dataEncryptionAlgorithm) {
			this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
			return this;
		}

		public Builder defaultDigest(Saml2DigestMethod defaultDigest) {
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

		public Builder nameIds(List<Saml2NameId> nameIds) {
			this.nameIds = nameIds;
			return this;
		}

		public Builder nameIds(Saml2NameId... nameIds) {
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

		public Builder providers(List<ExternalSaml2ServiceProviderRegistration> providers) {
			this.providers = providers;
			return this;
		}

		public Builder providers(ExternalSaml2ServiceProviderRegistration... providers) {
			this.providers = asList(providers);
			return this;
		}

		public HostedSaml2IdentityProviderRegistration build() {
			HostedSaml2IdentityProviderRegistration hostedIdentityProviderRegistration =
				new HostedSaml2IdentityProviderRegistration(
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
			return hostedIdentityProviderRegistration;
		}
	}
}
