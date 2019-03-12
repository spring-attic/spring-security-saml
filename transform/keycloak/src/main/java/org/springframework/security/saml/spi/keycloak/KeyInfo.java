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

package org.springframework.security.saml.spi.keycloak;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.SamlKeyStoreProvider;

import static org.springframework.util.StringUtils.hasText;

class KeyInfo {
	private final KeyPair keyPair;
	private X509Certificate certificate;

	KeyInfo(SamlKeyStoreProvider provider, KeyData key) throws UnrecoverableKeyException, NoSuchAlgorithmException,
															   KeyStoreException {
		KeyStore keyStore = provider.getKeyStore(key, key.getId().toCharArray());
		PrivateKey privateKey = hasText(key.getPrivateKey()) ?
			(PrivateKey) keyStore.getKey(key.getId(), key.getPassphrase().toCharArray()) :
			null;
		certificate = (X509Certificate) keyStore.getCertificate(key.getId());
		keyPair = new KeyPair(certificate.getPublicKey(), privateKey);
	}

	KeyPair getKeyPair() {
		return keyPair;
	}

	X509Certificate getCertificate() {
		return certificate;
	}
}
