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

package org.springframework.security.saml2.configuration;

import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.util.Assert;

import static org.springframework.util.StringUtils.hasText;

/**
 * Immutable configuration object that represents an external identity provider
 */
public class ExternalSaml2IdentityProviderConfiguration extends
	ExternalSaml2ProviderConfiguration<ExternalSaml2IdentityProviderConfiguration> {

	private final Saml2NameId nameId;
	private final int assertionConsumerServiceIndex;
	private final Saml2Binding authenticationRequestBinding;

	/**
	 * Creates a configuration representation of an external identity provider
	 *
	 * @param alias              - the alias for this provider. should be unique within the local system
	 * @param metadata           - XML metadata or URL location of XML metadata of this provider
	 * @param linktext           - Text to be displayed on the
	 * @param skipSslValidation  - set to true if you wish to disable TLS/SSL certificate validation when fetching
	 *                           metadata
	 * @param metadataTrustCheck - set to true if you wish to validate metadata signature against known keys
	 * @param nameId             - set to a non null value if a specific NameId format is to be used in the
	 *                           authentication request
	 * @param verificationKeys   - list of certificates, required if metadataTrustCheck is set to true
	 */
	public ExternalSaml2IdentityProviderConfiguration(String alias,
													  String metadata,
													  String linktext,
													  boolean skipSslValidation,
													  boolean metadataTrustCheck,
													  Saml2NameId nameId,
													  int assertionConsumerServiceIndex,
													  List<Saml2KeyData> verificationKeys,
													  Saml2Binding authenticationRequestBinding) {
		super(alias, metadata, linktext, skipSslValidation, metadataTrustCheck, verificationKeys);
		this.nameId = nameId;
		this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
		this.authenticationRequestBinding = authenticationRequestBinding;
	}

	public Saml2NameId getNameId() {
		return nameId;
	}

	public int getAssertionConsumerServiceIndex() {
		return assertionConsumerServiceIndex;
	}

	public Saml2Binding getAuthenticationRequestBinding() {
		return authenticationRequestBinding;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder builder(ExternalSaml2IdentityProviderConfiguration idp) {
		return builder()
			.alias(idp.getAlias())
			.metadata(idp.getMetadata())
			.assertionConsumerServiceIndex(idp.getAssertionConsumerServiceIndex())
			.metadataTrustCheck(idp.isMetadataTrustCheck())
			.skipSslValidation(idp.isSkipSslValidation())
			.nameId(idp.getNameId())
			.linktext(idp.getLinktext())
			.verificationKeys(idp.getVerificationKeys())
			;

	}

	public static final class Builder {
		private String alias;
		private String metadata;
		private String linktext;
		private boolean skipSslValidation;
		private Saml2NameId nameId;
		private int assertionConsumerServiceIndex;
		private boolean metadataTrustCheck;
		private List<Saml2KeyData> verificationKeys = new LinkedList<>();
		private Saml2Binding authenticationRequestBinding = Saml2Binding.REDIRECT;

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

		public Builder nameId(Saml2NameId nameId) {
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

		public Builder verificationKeys(List<Saml2KeyData> verificationKeys) {
			this.verificationKeys = new LinkedList<>(verificationKeys);
			return this;
		}

		public Builder addVerificationKey(Saml2KeyData verificationKey) {
			this.verificationKeys.add(verificationKey);
			return this;
		}

		public Builder authenticationRequestBinding(Saml2Binding binding) {
			this.authenticationRequestBinding = binding;
			return this;
		}

		public ExternalSaml2IdentityProviderConfiguration build() {
			Assert.notNull(alias, "Alias is required");
			Assert.notNull(metadata, "Metadata is required");
			return new ExternalSaml2IdentityProviderConfiguration(
				alias,
				metadata,
				hasText(linktext) ? linktext : alias,
				skipSslValidation,
				metadataTrustCheck,
				nameId,
				assertionConsumerServiceIndex,
				verificationKeys,
				authenticationRequestBinding
			);
		}
	}
}
