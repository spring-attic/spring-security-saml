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

package org.springframework.security.saml.saml2.key;

public class KeyData {

	private final String id;
	private final String privateKey;
	private final String certificate;
	private final String passphrase;
	private final KeyType type;

	public KeyData(String id,
				   String privateKey,
				   String certificate,
				   String passphrase,
				   KeyType type) {
		this.id = id;
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.passphrase = passphrase;
		this.type = type;
	}

	public KeyData(KeyData other) {
		this(
			other.getId(),
			other.getPrivateKey(),
			other.getCertificate(),
			other.getPassphrase(),
			other.getType()
		);
	}

	public String getId() {
		return id;
	}

	public KeyType getType() {
		return type;
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


	public static final class KeyDataBuilder {
		private String id;
		private String privateKey;
		private String certificate;
		private String passphrase;
		private KeyType type = KeyType.SIGNING;

		private KeyDataBuilder() {
		}

		public static KeyDataBuilder builder() {
			return new KeyDataBuilder();
		}

		public static KeyDataBuilder builder(KeyData data) {
			return builder()
				.withCertificate(data.getCertificate())
				.withId(data.getId())
				.withPassphrase(data.getPassphrase())
				.withPrivateKey(data.getPrivateKey())
				.withType(data.getType());
		}

		public KeyDataBuilder withId(String name) {
			this.id = name;
			return this;
		}

		public KeyDataBuilder withPrivateKey(String privateKey) {
			this.privateKey = privateKey;
			return this;
		}

		public KeyDataBuilder withCertificate(String certificate) {
			this.certificate = certificate;
			return this;
		}

		public KeyDataBuilder withPassphrase(String passphrase) {
			this.passphrase = passphrase;
			return this;
		}

		public KeyDataBuilder withType(KeyType type) {
			this.type = type;
			return this;
		}

		public KeyData build() {
			return new KeyData(id, privateKey, certificate, passphrase, type);
		}
	}
}
