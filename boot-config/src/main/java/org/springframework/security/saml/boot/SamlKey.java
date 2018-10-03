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

import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;

public class SamlKey {
	private String name;
	private String privateKey;
	private String certificate;
	private String passphrase;
	private KeyType type;

	public SamlKey() {
	}

	public SamlKey(String name,
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

	public SimpleKey toSimpleKey() {
		return new SimpleKey(
			getName(),
			getPrivateKey(),
			getCertificate(),
			getPassphrase(),
			getType()
		);
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public String getPassphrase() {
		return passphrase;
	}

	public void setPassphrase(String passphrase) {
		this.passphrase = passphrase;
	}

	public KeyType getType() {
		return type;
	}

	public void setType(KeyType type) {
		this.type = type;
	}
}
