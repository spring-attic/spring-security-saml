/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.provider.identity.config;

import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;

public class LocalIdentityProviderConfiguration extends
	LocalProviderConfiguration<LocalIdentityProviderConfiguration, ExternalServiceProviderConfiguration> {

	private boolean wantRequestsSigned = true;
	private boolean signAssertions = true;
	private boolean encryptAssertions = false;
	private KeyEncryptionMethod keyEncryptionAlgorithm = KeyEncryptionMethod.RSA_1_5;
	private DataEncryptionMethod dataEncryptionAlgorithm = DataEncryptionMethod.AES256_CBC;
	private long notOnOrAfter = 120000;
	private long notBefore = 60000;
	private long sessionNotOnOrAfter = 30 * 60 * 1000;

	public LocalIdentityProviderConfiguration() {
		super("saml/idp/");
	}

	public boolean isWantRequestsSigned() {
		return wantRequestsSigned;
	}

	public LocalIdentityProviderConfiguration setWantRequestsSigned(boolean wantRequestsSigned) {
		this.wantRequestsSigned = wantRequestsSigned;
		return this;
	}

	public boolean isSignAssertions() {
		return signAssertions;
	}

	public LocalIdentityProviderConfiguration setSignAssertions(boolean signAssertions) {
		this.signAssertions = signAssertions;
		return this;
	}

	public long getNotOnOrAfter() {
		return notOnOrAfter;
	}

	public LocalIdentityProviderConfiguration setNotOnOrAfter(long notOnOrAfter) {
		this.notOnOrAfter = notOnOrAfter;
		return this;
	}

	public long getNotBefore() {
		return notBefore;
	}

	public LocalIdentityProviderConfiguration setNotBefore(long notBefore) {
		this.notBefore = notBefore;
		return this;
	}

	public long getSessionNotOnOrAfter() {
		return sessionNotOnOrAfter;
	}

	public LocalIdentityProviderConfiguration setSessionNotOnOrAfter(long sessionNotOnOrAfter) {
		this.sessionNotOnOrAfter = sessionNotOnOrAfter;
		return this;
	}

	public boolean isEncryptAssertions() {
		return encryptAssertions;
	}

	public LocalIdentityProviderConfiguration setEncryptAssertions(boolean encryptAssertions) {
		this.encryptAssertions = encryptAssertions;
		return this;
	}

	public KeyEncryptionMethod getKeyEncryptionAlgorithm() {
		return keyEncryptionAlgorithm;
	}

	public LocalIdentityProviderConfiguration setKeyEncryptionAlgorithm(KeyEncryptionMethod keyEncryptionAlgorithm) {
		this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
		return this;
	}

	public DataEncryptionMethod getDataEncryptionAlgorithm() {
		return dataEncryptionAlgorithm;
	}

	public LocalIdentityProviderConfiguration setDataEncryptionAlgorithm(DataEncryptionMethod dataEncryptionAlgorithm) {
		this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
		return this;
	}
}
