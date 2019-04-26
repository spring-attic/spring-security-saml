/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml2.spi;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.UUID;

import org.springframework.security.saml2.Saml2KeyException;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.util.Saml2X509Utils;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public interface Saml2KeyStoreProvider {

	char[] DEFAULT_KS_PASSWD = ("ks" + UUID.randomUUID().toString()).toCharArray();

	default KeyStore getKeyStore(Saml2KeyData key) {
		return getKeyStore(key, DEFAULT_KS_PASSWD);
	}

	default KeyStore getKeyStore(Saml2KeyData key, char[] keystorePassword) {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null, keystorePassword);

			byte[] certbytes = Saml2X509Utils.getDER(key.getCertificate());
			Certificate certificate = Saml2X509Utils.getCertificate(certbytes);
			ks.setCertificateEntry(key.getId(), certificate);

			if (hasText(key.getPrivateKey())) {
				PrivateKey pkey = Saml2X509Utils.readPrivateKey(key.getPrivateKey(), key.getPassphrase());
				ks.setKeyEntry(key.getId(), pkey, key.getPassphrase().toCharArray(), new Certificate[]{certificate});
				char[] passphrase = (ofNullable(key.getPassphrase()).orElse("")).toCharArray();
				ks.setKeyEntry(key.getId(), pkey, passphrase, new Certificate[]{certificate});
			}

			return ks;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			throw new Saml2KeyException(e);
		} catch (IOException e) {
			throw new Saml2KeyException(e);
		}
	}

}
