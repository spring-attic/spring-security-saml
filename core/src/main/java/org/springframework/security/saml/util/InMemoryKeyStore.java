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
/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.util;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.UUID;

import org.springframework.security.saml.key.SimpleKey;

import static org.springframework.util.StringUtils.hasText;

public class InMemoryKeyStore {

	private static final char[] KS_PASSWD = UUID.randomUUID().toString().toCharArray();
	private KeyStore ks;

	public InMemoryKeyStore(KeyStore ks) {
		this.ks = ks;
	}

	public static InMemoryKeyStore fromKey(SimpleKey key) {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null, KS_PASSWD);

			byte[] certbytes = X509Utilities.getDER(key.getCertificate());
			Certificate certificate = X509Utilities.getCertificate(certbytes);
			ks.setCertificateEntry(key.getName(), certificate);

			if (hasText(key.getPrivateKey())) {
				PrivateKey pkey = X509Utilities.readPrivateKey(key.getPrivateKey(), key.getPassphrase());

				//RSAPrivateKey privateKey = X509Utilities.getPrivateKey(keybytes, "RSA");

				ks.setKeyEntry(key.getName(), pkey, key.getPassphrase().toCharArray(), new
					Certificate[]{certificate});
			}

			return new InMemoryKeyStore(ks);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public KeyStore getKeyStore() {
		return ks;
	}


}
