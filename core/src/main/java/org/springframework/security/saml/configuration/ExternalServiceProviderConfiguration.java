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

import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.util.Assert;

import static org.springframework.util.StringUtils.hasText;

/**
 * Immutable configuration object that represents an external service provider
 */
public class ExternalServiceProviderConfiguration extends
	ExternalProviderConfiguration<ExternalServiceProviderConfiguration> {

	/**
	 * Creates a configuration representation of an external service provider
	 *
	 * @param alias              - the alias for this provider. should be unique within the local system
	 * @param metadata           - XML metadata or URL location of XML metadata of this provider
	 * @param linktext           - Text to be displayed on the provider selection page
	 * @param skipSslValidation  - set to true if you wish to disable TLS/SSL certificate validation when fetching
	 *                           metadata
	 * @param metadataTrustCheck - set to true if you wish to validate metadata signature against known keys
	 * @param verificationKeys   - list of certificates, required if metadataTrustCheck is set to true
	 */
	public ExternalServiceProviderConfiguration(String alias,
												String metadata,
												String linktext,
												boolean skipSslValidation,
												boolean metadataTrustCheck,
												List<KeyData> verificationKeys) {
		super(alias, metadata, linktext, skipSslValidation, metadataTrustCheck, verificationKeys);
	}

	public static ExternalServiceProviderConfiguration.Builder builder() {
		return new ExternalServiceProviderConfiguration.Builder();
	}

	public static ExternalServiceProviderConfiguration.Builder builder(ExternalServiceProviderConfiguration idp) {
		return builder()
			.alias(idp.getAlias())
			.metadata(idp.getMetadata())
			.metadataTrustCheck(idp.isMetadataTrustCheck())
			.skipSslValidation(idp.isSkipSslValidation())
			.linktext(idp.getLinktext())
			.verificationKeys(idp.getVerificationKeys())
			;

	}

	public static final class Builder {
		private String alias;
		private String metadata;
		private String linktext;
		private boolean skipSslValidation;
		private boolean metadataTrustCheck;
		private List<KeyData> verificationKeys = new LinkedList<>();

		private Builder() {
		}

		public ExternalServiceProviderConfiguration.Builder alias(String alias) {
			this.alias = alias;
			return this;
		}

		public ExternalServiceProviderConfiguration.Builder metadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public ExternalServiceProviderConfiguration.Builder linktext(String linktext) {
			this.linktext = linktext;
			return this;
		}

		public ExternalServiceProviderConfiguration.Builder skipSslValidation(boolean skipSslValidation) {
			this.skipSslValidation = skipSslValidation;
			return this;
		}

		public ExternalServiceProviderConfiguration.Builder metadataTrustCheck(boolean metadataTrustCheck) {
			this.metadataTrustCheck = metadataTrustCheck;
			return this;
		}

		public ExternalServiceProviderConfiguration.Builder verificationKeys(List<KeyData> verificationKeys) {
			this.verificationKeys = new LinkedList<>(verificationKeys);
			return this;
		}

		public ExternalServiceProviderConfiguration.Builder addVerificationKey(KeyData verificationKey) {
			this.verificationKeys.add(verificationKey);
			return this;
		}

		public ExternalServiceProviderConfiguration build() {
			Assert.notNull(alias, "Alias is required");
			Assert.notNull(metadata, "Metadata is required");
			return new ExternalServiceProviderConfiguration(
				alias,
				metadata,
				hasText(linktext) ? linktext : alias,
				skipSslValidation,
				metadataTrustCheck,
				verificationKeys
			);
		}
	}
}
