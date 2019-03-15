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

package org.springframework.security.saml.key;

public class SimpleKey implements Cloneable {

	private String name;
	private String privateKey;
	private String certificate;
	private String passphrase;
	private KeyType type;

	public SimpleKey() {
	}

	public SimpleKey(String name,
					 String privateKey,
					 String certificate,
					 String passphrase,
					 KeyType type) {
		this.name = name;
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.passphrase = passphrase;
		this.type = type;
	}

	public String getName() {
		return name;
	}

	public SimpleKey setName(String name) {
		this.name = name;
		return this;
	}

	public KeyType getType() {
		return type;
	}

	public SimpleKey setType(KeyType type) {
		this.type = type;
		return this;
	}

	public SimpleKey clone(String alias, KeyType type) {
		return new SimpleKey(alias, getPrivateKey(), getCertificate(), getPassphrase(), type);
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public String getCertificate() {
		return certificate;
	}

	public String getPassphrase() {
		return passphrase;
	}

	public SimpleKey setPassphrase(String passphrase) {
		this.passphrase = passphrase;
		return this;
	}

	public SimpleKey setCertificate(String certificate) {
		this.certificate = certificate;
		return this;
	}

	public SimpleKey setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
		return this;
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}
}
