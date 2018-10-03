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

public abstract class RemoteProviderConfiguration {
	private String alias;
	private String metadata;
	private String linktext;
	private boolean skipSslValidation = false;
	private boolean metadataTrustCheck = false;

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getMetadata() {
		return metadata;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public String getLinktext() {
		return linktext;
	}

	public void setLinktext(String linktext) {
		this.linktext = linktext;
	}

	public boolean isSkipSslValidation() {
		return skipSslValidation;
	}

	public void setSkipSslValidation(boolean skipSslValidation) {
		this.skipSslValidation = skipSslValidation;
	}

	public boolean isMetadataTrustCheck() {
		return metadataTrustCheck;
	}

	public void setMetadataTrustCheck(boolean metadataTrustCheck) {
		this.metadataTrustCheck = metadataTrustCheck;
	}


}
