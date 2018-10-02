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

import org.springframework.security.saml.provider.service.config.HostedServiceProviderConfiguration;

public class LocalServiceProviderConfiguration extends
	LocalProviderConfiguration<RemoteIdentityProviderConfiguration> {

	private boolean signRequests = false;
	private boolean wantAssertionsSigned = false;

	public LocalServiceProviderConfiguration() {
		super("saml/sp");
	}

	public boolean isSignRequests() {
		return signRequests;
	}

	public void setSignRequests(boolean signRequests) {
		this.signRequests = signRequests;
	}

	public boolean isWantAssertionsSigned() {
		return wantAssertionsSigned;
	}

	public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
		this.wantAssertionsSigned = wantAssertionsSigned;
	}

	public HostedServiceProviderConfiguration toHostedConfiguration() {
		return new HostedServiceProviderConfiguration(
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
			getProviders().stream().map(p -> p.toExternalIdentityProviderConfiguration()).collect(Collectors.toList()),
			isSignRequests(),
			isWantAssertionsSigned()
		);
	}
}
