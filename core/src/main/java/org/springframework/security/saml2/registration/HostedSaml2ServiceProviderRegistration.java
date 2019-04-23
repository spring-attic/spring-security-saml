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

import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;

import static java.util.Arrays.asList;

/**
 * Immutable configuration object that represents a local service provider (SP) service.
 */
public class HostedSaml2ServiceProviderRegistration extends
	HostedSaml2ProviderRegistration<ExternalSaml2IdentityProviderRegistration> {

	private final boolean signRequests;
	private final boolean wantAssertionsSigned;

	public HostedSaml2ServiceProviderRegistration(String pathPrefix,
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
												  List<ExternalSaml2IdentityProviderRegistration> providers,
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

	public static Builder builder(HostedSaml2ServiceProviderRegistration registration) {
		return builder()
			.signRequests(registration.isSignRequests())
			.wantAssertionsSigned(registration.isWantAssertionsSigned())
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
		private boolean signRequests = true;
		private boolean wantAssertionsSigned = true;
		private String pathPrefix = "/saml/sp";
		private String basePath;
		private String alias;
		private String entityId;
		private boolean signMetadata = true;
		private String metadata;
		private List<Saml2KeyData> keys;
		private Saml2AlgorithmMethod defaultSigningAlgorithm = Saml2AlgorithmMethod.RSA_SHA256;
		private Saml2DigestMethod defaultDigest = Saml2DigestMethod.SHA256;
		private List<Saml2NameId> nameIds = asList(Saml2NameId.PERSISTENT, Saml2NameId.EMAIL);
		private boolean singleLogoutEnabled = true;
		private List<ExternalSaml2IdentityProviderRegistration> providers;

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

		public Builder keys(List<Saml2KeyData> keys) {
			this.keys = keys;
			return this;
		}

		public Builder keys(Saml2KeyData... keys) {
			this.keys = asList(keys);
			return this;
		}

		public Builder defaultSigningAlgorithm(Saml2AlgorithmMethod defaultSigningAlgorithm) {
			this.defaultSigningAlgorithm = defaultSigningAlgorithm;
			return this;
		}

		public Builder defaultDigest(Saml2DigestMethod defaultDigest) {
			this.defaultDigest = defaultDigest;
			return this;
		}

		public Builder nameIds(List<Saml2NameId> nameIds) {
			this.nameIds = nameIds;
			return this;
		}

		public Builder singleLogoutEnabled(boolean singleLogoutEnabled) {
			this.singleLogoutEnabled = singleLogoutEnabled;
			return this;
		}

		public Builder providers(List<ExternalSaml2IdentityProviderRegistration> providers) {
			this.providers = providers;
			return this;
		}

		public Builder providers(ExternalSaml2IdentityProviderRegistration... providers) {
			this.providers = asList(providers);
			return this;
		}

		public HostedSaml2ServiceProviderRegistration build() {
			HostedSaml2ServiceProviderRegistration hostedServiceProviderRegistration =
				new HostedSaml2ServiceProviderRegistration(
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
			return hostedServiceProviderRegistration;
		}
	}
}
