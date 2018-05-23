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

package org.springframework.security.saml.config;

public class ExternalProviderConfiguration<T extends ExternalProviderConfiguration> {
	private String name;
	private String metadata;
	private String linktext;
	private boolean skipSslValidation = false;

	public ExternalProviderConfiguration() {
	}

	public String getName() {
		return name;
	}

	public T setName(String name) {
		this.name = name;
		return _this();
	}

	@SuppressWarnings("checked")
	protected T _this() {
		return (T) this;
	}

	public String getMetadata() {
		return metadata;
	}

	public T setMetadata(String metadata) {
		this.metadata = metadata;
		return _this();
	}

	public String getLinktext() {
		return linktext;
	}

	public T setLinktext(String linktext) {
		this.linktext = linktext;
		return _this();
	}

	public boolean isSkipSslValidation() {
		return skipSslValidation;
	}

	public T setSkipSslValidation(boolean skipSslValidation) {
		this.skipSslValidation = skipSslValidation;
		return _this();
	}
}
