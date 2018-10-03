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

package org.springframework.security.saml.provider.config;

public abstract class ExternalProviderConfiguration<T extends ExternalProviderConfiguration> {
	private final String alias;
	private final String metadata;
	private final String linktext;
	private final boolean skipSslValidation;
	private final boolean metadataTrustCheck;

	public ExternalProviderConfiguration(String alias,
										 String metadata,
										 String linktext,
										 boolean skipSslValidation,
										 boolean metadataTrustCheck) {
		this.alias = alias;
		this.metadata = metadata;
		this.linktext = linktext;
		this.skipSslValidation = skipSslValidation;
		this.metadataTrustCheck = metadataTrustCheck;
	}

	public String getAlias() {
		return alias;
	}

	public String getMetadata() {
		return metadata;
	}

	public String getLinktext() {
		return linktext;
	}

	public boolean isSkipSslValidation() {
		return skipSslValidation;
	}

	public boolean isMetadataTrustCheck() {
		return metadataTrustCheck;
	}

}
