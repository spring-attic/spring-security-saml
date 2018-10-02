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

package org.springframework.security.saml.provider.service.config;

import java.util.List;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.HostedProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

public class HostedServiceProviderConfiguration extends
	HostedProviderConfiguration<ExternalIdentityProviderConfiguration> {

	private final boolean signRequests;
	private final boolean wantAssertionsSigned;

	public HostedServiceProviderConfiguration(String prefix,
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
											  List<ExternalIdentityProviderConfiguration> providers,
											  boolean signRequests, boolean wantAssertionsSigned) {
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
		this.signRequests = signRequests;
		this.wantAssertionsSigned = wantAssertionsSigned;
	}

	public boolean isSignRequests() {
		return signRequests;
	}

	public boolean isWantAssertionsSigned() {
		return wantAssertionsSigned;
	}


}
