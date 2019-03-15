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
package org.springframework.security.saml.util;

import java.io.ByteArrayInputStream;
import java.io.CharArrayReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.security.saml.SamlKeyException;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class X509Utilities {

	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
	public static final String END_CERT = "-----END CERTIFICATE-----";
	public static final String BEGIN_KEY = "-----BEGIN RSA PRIVATE KEY-----\n";
	public static final String END_KEY = "-----END RSA PRIVATE KEY-----";

	public static byte[] getDER(
		String combinedKeyAndCertPem,
		String begin,
		String end
	) {
		String[] tokens = combinedKeyAndCertPem.split(begin);
		tokens = tokens[0].split(end);
		return getDER(tokens[0]);
	}

	public static byte[] getDER(String pem) {
		String data = keyCleanup(pem);

		return DatatypeConverter.parseBase64Binary(data);
	}

	public static String keyCleanup(String pem) {
		return pem
			.replace(BEGIN_CERT, "")
			.replace(END_CERT, "")
			.replace(BEGIN_KEY, "")
			.replace(END_KEY, "")
			.replace("\n", "")
			.trim();
	}

	public static X509Certificate getCertificate(byte[] der) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
	}

	public static RSAPrivateKey getPrivateKey(byte[] der, String algorithm)
		throws InvalidKeySpecException, NoSuchAlgorithmException {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
		KeyFactory factory = KeyFactory.getInstance(algorithm);
		return (RSAPrivateKey) factory.generatePrivate(spec);
	}

	public static PrivateKey readPrivateKey(String pem, String passphrase) {

		try {
			PEMParser parser = new PEMParser(new CharArrayReader(pem.toCharArray()));
			Object obj = parser.readObject();
			parser.close();
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			KeyPair kp;
			if (obj == null) {
				throw new SamlKeyException("Unable to decode PEM key:" + pem);
			}
			else if (obj instanceof PEMEncryptedKeyPair) {
				// Encrypted key - we will use provided password
				PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passphrase
					.toCharArray());
				kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
			}
			else {
				// Unencrypted key - no password needed
				PEMKeyPair ukp = (PEMKeyPair) obj;
				kp = converter.getKeyPair(ukp);
			}

			return kp.getPrivate();
		} catch (IOException e) {
			throw new SamlKeyException(e);
		}
	}

}
