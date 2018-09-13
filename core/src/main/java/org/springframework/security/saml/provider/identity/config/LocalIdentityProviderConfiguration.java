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

	public static class Builder extends LocalProviderConfiguration.Builder<LocalIdentityProviderConfiguration, ExternalServiceProviderConfiguration, Builder>{

        @Override
        protected LocalIdentityProviderConfiguration createLocalProviderConfigurationInstance() {
            return new LocalIdentityProviderConfiguration();
        }

        @Override
        public LocalIdentityProviderConfiguration build() {
            return localProviderConfiguration;
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder setWantRequestsSigned(boolean wantRequestsSigned) {
            localProviderConfiguration.wantRequestsSigned = wantRequestsSigned;
            return this;
        }

        public Builder setSignAssertions(boolean signAssertions) {
            localProviderConfiguration.signAssertions = signAssertions;
            return this;
        }

        public Builder setNotOnOrAfter(long notOnOrAfter) {
            localProviderConfiguration.notOnOrAfter = notOnOrAfter;
            return this;
        }

        public Builder setNotBefore(long notBefore) {
            localProviderConfiguration.notBefore = notBefore;
            return this;
        }

        public Builder setSessionNotOnOrAfter(long sessionNotOnOrAfter) {
            localProviderConfiguration.sessionNotOnOrAfter = sessionNotOnOrAfter;
            return this;
        }

        public Builder setEncryptAssertions(boolean encryptAssertions) {
            localProviderConfiguration.encryptAssertions = encryptAssertions;
            return this;
        }

        public Builder setKeyEncryptionAlgorithm(KeyEncryptionMethod keyEncryptionAlgorithm) {
            localProviderConfiguration.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            return this;
        }

        public Builder setDataEncryptionAlgorithm(DataEncryptionMethod dataEncryptionAlgorithm) {
            localProviderConfiguration.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
            return this;
        }
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

	public boolean isEncryptAssertions() {
		return encryptAssertions;
	}

	public void setEncryptAssertions(boolean encryptAssertions) {
		this.encryptAssertions = encryptAssertions;
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
}
