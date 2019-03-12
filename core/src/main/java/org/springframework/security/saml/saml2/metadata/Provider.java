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
package org.springframework.security.saml.saml2.metadata;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.xml.datatype.Duration;

import org.springframework.security.saml.saml2.Namespace;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.signature.Signature;

import org.joda.time.DateTime;

import static java.util.Arrays.asList;

/**
 * Base class for SAML providers
 *
 * @param <T> return class for builder pattern
 */
public class Provider<T extends Provider<T>> {

	private Signature signature;
	private List<KeyData> keys = new LinkedList<>();
	private String id;
	private DateTime validUntil;
	private Duration cacheDuration;
	private List<String> protocolSupportEnumeration = asList(Namespace.NS_PROTOCOL);

	public Signature getSignature() {
		return signature;
	}

	public T setSignature(Signature signature) {
		this.signature = signature;
		return (T) this;
	}

	public List<KeyData> getKeys() {
		return Collections.unmodifiableList(keys);
	}

	public T setKeys(List<KeyData> keys) {
		this.keys.clear();
		if (keys != null) {
			this.keys.addAll(keys);
		}
		return _this();
	}

	@SuppressWarnings("unchecked")
	protected T _this() {
		return (T) this;
	}

	public String getId() {
		return id;
	}

	public T setId(String id) {
		this.id = id;
		return (T) this;
	}

	public DateTime getValidUntil() {
		return validUntil;
	}

	public T setValidUntil(DateTime validUntil) {
		this.validUntil = validUntil;
		return (T) this;
	}

	public Duration getCacheDuration() {
		return cacheDuration;

	}

	public T setCacheDuration(Duration cacheDuration) {
		this.cacheDuration = cacheDuration;
		return (T) this;
	}

	public List<String> getProtocolSupportEnumeration() {
		return protocolSupportEnumeration;
	}

	public T setProtocolSupportEnumeration(List<String> protocolSupportEnumeration) {
		this.protocolSupportEnumeration = protocolSupportEnumeration;
		return (T) this;
	}
}
