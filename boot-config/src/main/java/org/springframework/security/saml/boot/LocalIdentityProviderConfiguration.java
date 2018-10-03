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

package org.springframework.security.saml.boot;

import java.util.stream.Collectors;

import org.springframework.security.saml.provider.identity.config.HostedIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;

public class LocalIdentityProviderConfiguration extends
	LocalProviderConfiguration<RemoteServiceProviderConfiguration> {

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

	public void setWantRequestsSigned(boolean wantRequestsSigned) {
		this.wantRequestsSigned = wantRequestsSigned;
	}

	public boolean isSignAssertions() {
		return signAssertions;
	}

	public void setSignAssertions(boolean signAssertions) {
		this.signAssertions = signAssertions;
	}

	public boolean isEncryptAssertions() {
		return encryptAssertions;
	}

	public void setEncryptAssertions(boolean encryptAssertions) {
		this.encryptAssertions = encryptAssertions;
	}

	public HostedIdentityProviderConfiguration toHostedConfiguration() {
		return new HostedIdentityProviderConfiguration(
			getPrefix(),
			getBasePath(),
			getAlias(),
			getEntityId(),
			isSignMetadata(),
			getMetadata(),
			getKeys().toList(),
			getDefaultSigningAlgorithm(),
			getDefaultDigest(),
			getNameIds(),
			isSingleLogoutEnabled(),
			getProviders().stream().map(p -> p.toExternalServiceProviderConfiguration()).collect(Collectors.toList()),
			getKeyEncryptionAlgorithm(),
			getDataEncryptionAlgorithm(),
			getNotOnOrAfter(),
			getNotBefore(),
			getSessionNotOnOrAfter()
		);
	}

	public KeyEncryptionMethod getKeyEncryptionAlgorithm() {
		return keyEncryptionAlgorithm;
	}

	public void setKeyEncryptionAlgorithm(KeyEncryptionMethod keyEncryptionAlgorithm) {
		this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
	}

	public DataEncryptionMethod getDataEncryptionAlgorithm() {
		return dataEncryptionAlgorithm;
	}

	public void setDataEncryptionAlgorithm(DataEncryptionMethod dataEncryptionAlgorithm) {
		this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
	}

	public long getNotOnOrAfter() {
		return notOnOrAfter;
	}

	public void setNotOnOrAfter(long notOnOrAfter) {
		this.notOnOrAfter = notOnOrAfter;
	}

	public long getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(long notBefore) {
		this.notBefore = notBefore;
	}

	public long getSessionNotOnOrAfter() {
		return sessionNotOnOrAfter;
	}

	public void setSessionNotOnOrAfter(long sessionNotOnOrAfter) {
		this.sessionNotOnOrAfter = sessionNotOnOrAfter;
	}
}
