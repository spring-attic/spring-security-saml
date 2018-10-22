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

}
