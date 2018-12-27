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

/**
 * Immutable configuration object that represents an external service provider
 */
public class ExternalServiceProviderConfiguration extends
	ExternalProviderConfiguration<ExternalServiceProviderConfiguration> {

	/**
	 * Creates a configuration representation of an external service provider
	 *
	 * @param alias              - the alias for this provider. should be unique within the local system
	 * @param metadata           - XML metadata or URL location of XML metadata of this provider
	 * @param linktext           - Text to be displayed on the provider selection page
	 * @param skipSslValidation  - set to true if you wish to disable TLS/SSL certificate validation when fetching
	 *                           metadata
	 * @param metadataTrustCheck - set to true if you wish to validate metadata against known keys (not used)
	 */
	public ExternalServiceProviderConfiguration(String alias,
												String metadata,
												String linktext,
												boolean skipSslValidation,
												boolean metadataTrustCheck) {
		super(alias, metadata, linktext, skipSslValidation, metadataTrustCheck);
	}
}
