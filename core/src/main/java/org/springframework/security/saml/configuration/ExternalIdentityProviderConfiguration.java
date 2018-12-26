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

package org.springframework.security.saml.configuration;

import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.util.Assert;

import static org.springframework.util.StringUtils.hasText;

public class ExternalIdentityProviderConfiguration extends
	ExternalProviderConfiguration<ExternalIdentityProviderConfiguration> {

	private final NameId nameId;
	private final int assertionConsumerServiceIndex;

	ExternalIdentityProviderConfiguration(String alias,
										  String metadata,
										  String linktext,
										  boolean skipSslValidation,
										  boolean metadataTrustCheck,
										  NameId nameId, int assertionConsumerServiceIndex) {
		super(alias, metadata, linktext, skipSslValidation, metadataTrustCheck);
		this.nameId = nameId;
		this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
	}

	public static Builder builder(ExternalIdentityProviderConfiguration idp) {
		return builder()
			.alias(idp.getAlias())
			.metadata(idp.getMetadata())
			.assertionConsumerServiceIndex(idp.getAssertionConsumerServiceIndex())
			.metadataTrustCheck(idp.isMetadataTrustCheck())
			.skipSslValidation(idp.isSkipSslValidation())
			.nameId(idp.getNameId())
			.linktext(idp.getLinktext())
			;

	}

	public static Builder builder() {
		return new Builder();
	}

	public int getAssertionConsumerServiceIndex() {
		return assertionConsumerServiceIndex;
	}

	public NameId getNameId() {
		return nameId;
	}

	public static final class Builder {
		private String alias;
		private String metadata;
		private String linktext;
		private boolean skipSslValidation;
		private NameId nameId;
		private int assertionConsumerServiceIndex;
		private boolean metadataTrustCheck;

		private Builder() {
		}

		public Builder alias(String alias) {
			this.alias = alias;
			return this;
		}

		public Builder metadata(String metadata) {
			this.metadata = metadata;
			return this;
		}

		public Builder linktext(String linktext) {
			this.linktext = linktext;
			return this;
		}

		public Builder skipSslValidation(boolean skipSslValidation) {
			this.skipSslValidation = skipSslValidation;
			return this;
		}

		public Builder nameId(NameId nameId) {
			this.nameId = nameId;
			return this;
		}

		public Builder assertionConsumerServiceIndex(int assertionConsumerServiceIndex) {
			this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
			return this;
		}

		public Builder metadataTrustCheck(boolean metadataTrustCheck) {
			this.metadataTrustCheck = metadataTrustCheck;
			return this;
		}

		public ExternalIdentityProviderConfiguration build() {
			Assert.notNull(alias, "Alias is required");
			Assert.notNull(metadata, "Metadata is required");
			return new ExternalIdentityProviderConfiguration(
				alias,
				metadata,
				hasText(linktext) ? linktext : alias,
				skipSslValidation,
				metadataTrustCheck,
				nameId,
				assertionConsumerServiceIndex
			);
		}
	}
}
