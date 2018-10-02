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

package org.springframework.security.saml.provider.identity.config;

import java.util.List;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.HostedProviderConfiguration;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

public class HostedIdentityProviderConfiguration extends
	HostedProviderConfiguration<ExternalServiceProviderConfiguration> {

	private final boolean wantRequestsSigned = true;
	private final boolean signAssertions = true;
	private final boolean encryptAssertions = false;
	private final KeyEncryptionMethod keyEncryptionAlgorithm;
	private final DataEncryptionMethod dataEncryptionAlgorithm;
	private final long notOnOrAfter;
	private final long notBefore;
	private final long sessionNotOnOrAfter;

	public HostedIdentityProviderConfiguration(String prefix,
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
											   List<ExternalServiceProviderConfiguration> providers,
											   KeyEncryptionMethod keyEncryptionAlgorithm,
											   DataEncryptionMethod dataEncryptionAlgorithm,
											   long notOnOrAfter,
											   long notBefore, long sessionNotOnOrAfter) {
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

}
