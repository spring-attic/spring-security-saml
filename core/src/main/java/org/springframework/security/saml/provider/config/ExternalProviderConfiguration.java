/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.provider.config;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.saml.key.SimpleKey;

import static java.util.Optional.ofNullable;

public class ExternalProviderConfiguration<T extends ExternalProviderConfiguration> implements Cloneable {
	private String alias;
	private String metadata;
	private String linktext;
	private boolean skipSslValidation = false;
	private boolean metadataTrustCheck = false;
	private List<String> verificationKeys = new LinkedList<>();

	public ExternalProviderConfiguration() {
	}

	public String getAlias() {
		return alias;
	}

	public T setAlias(String alias) {
		this.alias = alias;
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

	public boolean isMetadataTrustCheck() {
		return metadataTrustCheck;
	}

	public T setMetadataTrustCheck(boolean metadataTrustCheck) {
		this.metadataTrustCheck = metadataTrustCheck;
		return _this();
	}

	public List<String> getVerificationKeys() {
		return ofNullable(verificationKeys).orElse(Collections.emptyList());
	}

	public T setVerificationKeys(List<String> verificationKeys) {
		this.verificationKeys = verificationKeys;
		return _this();
	}

	public List<SimpleKey> getVerificationKeyData() {
		return getVerificationKeys()
			.stream()
			.map(
				s -> new SimpleKey()
					.setName("from-config-"+UUID.randomUUID().toString())
					.setCertificate(s)
			)
			.collect(Collectors.toList());
	}

	@Override
	public T clone() throws CloneNotSupportedException {
		return (T) super.clone();
	}
}
