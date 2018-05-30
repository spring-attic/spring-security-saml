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

public class LocalProviderConfiguration<T extends LocalProviderConfiguration> {

	private String entityId;
	private String name;
	private boolean signMetadata;
	private String metadata;
	private RotatingKeys keys;
	private String prefix;


	public LocalProviderConfiguration(String prefix) {
		setPrefix(prefix);
	}

	public String getEntityId() {
		return entityId;
	}

	public T setEntityId(String entityId) {
		this.entityId = entityId;
		return _this();
	}

	@SuppressWarnings("checked")
	protected T _this() {
		return (T) this;
	}

	public boolean isSignMetadata() {
		return signMetadata;
	}

	public T setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
		return _this();
	}

	public String getMetadata() {
		return metadata;
	}

	public T setMetadata(String metadata) {
		this.metadata = metadata;
		return _this();
	}

	public RotatingKeys getKeys() {
		return keys;
	}

	public T setKeys(RotatingKeys keys) {
		this.keys = keys;
		return _this();
	}

	public String getName() {
		return name;
	}

	public LocalProviderConfiguration<T> setName(String name) {
		this.name = name;
		return this;
	}

	public String getPrefix() {
		return prefix;
	}

	public LocalProviderConfiguration<T> setPrefix(String prefix) {
		this.prefix = prefix;
		return this;
	}
}
