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

import org.springframework.security.saml.saml2.metadata.NameId;

public class ExternalIdentityProviderConfiguration extends
	ExternalProviderConfiguration<ExternalIdentityProviderConfiguration> {

	private final NameId nameId;
	private final int assertionConsumerServiceIndex;

	public ExternalIdentityProviderConfiguration(String alias,
												 String metadata,
												 String linktext,
												 boolean skipSslValidation,
												 boolean metadataTrustCheck,
												 NameId nameId, int assertionConsumerServiceIndex) {
		super(alias, metadata, linktext, skipSslValidation, metadataTrustCheck);
		this.nameId = nameId;
		this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
	}

	public NameId getNameId() {
		return nameId;
	}

	public int getAssertionConsumerServiceIndex() {
		return assertionConsumerServiceIndex;
	}


	public static final class ExternalIdentityProviderConfigurationBuilder {
		private String alias;
		private String metadata;
		private String linktext;
		private boolean skipSslValidation;
		private NameId nameId;
		private int assertionConsumerServiceIndex;
		private boolean metadataTrustCheck;

		private ExternalIdentityProviderConfigurationBuilder() {
		}

		public static ExternalIdentityProviderConfigurationBuilder builder() {
			return new ExternalIdentityProviderConfigurationBuilder();
		}

		public static ExternalIdentityProviderConfigurationBuilder builder(ExternalIdentityProviderConfiguration idp) {
			return new ExternalIdentityProviderConfigurationBuilder()
				.withAlias(idp.getAlias())
				.withMetadata(idp.getMetadata())
				.withAssertionConsumerServiceIndex(idp.getAssertionConsumerServiceIndex())
				.withMetadataTrustCheck(idp.isMetadataTrustCheck())
				.withSkipSslValidation(idp.isSkipSslValidation())
				.withNameId(idp.getNameId())
				.withLinktext(idp.getLinktext())
				;

		}

		public ExternalIdentityProviderConfigurationBuilder withAlias(String alias) {
			this.alias = alias;
			return this;
		}

		public ExternalIdentityProviderConfigurationBuilder withMetadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public ExternalIdentityProviderConfigurationBuilder withLinktext(String linktext) {
			this.linktext = linktext;
			return this;
		}

		public ExternalIdentityProviderConfigurationBuilder withSkipSslValidation(boolean skipSslValidation) {
			this.skipSslValidation = skipSslValidation;
			return this;
		}

		public ExternalIdentityProviderConfigurationBuilder withNameId(NameId nameId) {
			this.nameId = nameId;
			return this;
		}

		public ExternalIdentityProviderConfigurationBuilder withAssertionConsumerServiceIndex(int assertionConsumerServiceIndex) {
			this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
			return this;
		}

		public ExternalIdentityProviderConfigurationBuilder withMetadataTrustCheck(boolean metadataTrustCheck) {
			this.metadataTrustCheck = metadataTrustCheck;
			return this;
		}

		public ExternalIdentityProviderConfiguration build() {
			return new ExternalIdentityProviderConfiguration(
				alias,
				metadata,
				linktext,
				skipSslValidation,
				metadataTrustCheck,
				nameId,
				assertionConsumerServiceIndex
			);
		}
	}
}
