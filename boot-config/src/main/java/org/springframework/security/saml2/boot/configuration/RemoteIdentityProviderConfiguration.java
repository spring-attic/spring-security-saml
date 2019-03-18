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

package org.springframework.security.saml2.boot.configuration;

import java.net.URI;

import org.springframework.security.saml2.configuration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml2.model.metadata.Binding;
import org.springframework.security.saml2.model.metadata.NameId;

public class RemoteIdentityProviderConfiguration extends RemoteProviderConfiguration {

	private NameId nameId;
	private int assertionConsumerServiceIndex;
	private URI authenticationRequestBinding = null;

	public NameId getNameId() {
		return nameId;
	}

	public void setNameId(NameId nameId) {
		this.nameId = nameId;
	}

	public void setNameId(String nameId) {
		setNameId(NameId.fromUrn(nameId));
	}

	public int getAssertionConsumerServiceIndex() {
		return assertionConsumerServiceIndex;
	}

	public void setAssertionConsumerServiceIndex(int assertionConsumerServiceIndex) {
		this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
	}

	public URI getAuthenticationRequestBinding() {
		return authenticationRequestBinding;
	}

	public void setAuthenticationRequestBinding(URI authenticationRequestBinding) {
		this.authenticationRequestBinding = authenticationRequestBinding;
	}

	public ExternalIdentityProviderConfiguration toExternalIdentityProviderConfiguration() {
		return new ExternalIdentityProviderConfiguration(
			getAlias(),
			getMetadata(),
			getLinktext(),
			isSkipSslValidation(),
			isMetadataTrustCheck(),
			getNameId(),
			getAssertionConsumerServiceIndex(),
			getVerificationKeyData(),
			Binding.fromUrn(getAuthenticationRequestBinding())
		);
	}

}
