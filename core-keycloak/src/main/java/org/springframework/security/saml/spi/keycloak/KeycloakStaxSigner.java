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

package org.springframework.security.saml.spi.keycloak;

import java.io.Reader;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.signature.CanonicalizationMethod;
import org.springframework.security.saml.spi.SamlKeyStoreProvider;

import org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature;
import org.w3c.dom.Document;

import static org.keycloak.saml.common.util.DocumentUtil.getDocument;
import static org.keycloak.saml.common.util.DocumentUtil.getDocumentAsString;

class KeycloakStaxSigner {

	private final SamlKeyStoreProvider provider;

	KeycloakStaxSigner(SamlKeyStoreProvider provider) {
		this.provider = provider;
	}

	String sign(SignableSaml2Object signable, String xml) {
		try {
			KeyData key = signable.getSigningKey();

			KeyStore keyStore = provider.getKeyStore(key, key.getName().toCharArray());
			Key signingKey = keyStore.getKey(key.getName(), key.getPassphrase().toCharArray());
			X509Certificate signingCert = (X509Certificate) keyStore.getCertificate(key.getName());
			if (signable instanceof Metadata) {
			}
			else if (signable instanceof AuthenticationRequest) {
			}
			else if (signable instanceof Assertion) {
			}
			else if (signable instanceof Response) {
			}
			else {
				throw new UnsupportedOperationException("Unable to sign class:" + signable.getClass());
			}
			Reader xmlReader = new StringReader(xml);
			String result = signDOM(
				xmlReader,
				signable.getAlgorithm().toString(),
				signable.getDigest().toString(),
				signingKey,
				signingCert
			);
			return result;
		} catch (Exception e) {
			throw new SamlException(e);
		}
	}

	private String signDOM(
		Reader xmlReader,
		String algorithm,
		String digest,
		Key signingKey,
		X509Certificate signingCert
	) throws Exception {

		Document document = getDocument(xmlReader);
		SAML2Signature samlSignature = new SAML2Signature();
		samlSignature.setSignatureMethod(algorithm);
		samlSignature.setDigestMethod(digest);
		samlSignature.setNextSibling(samlSignature.getNextSiblingOfIssuer(document));
		samlSignature.setX509Certificate(signingCert);
		samlSignature.signSAMLDocument(
			document,
			"signing",
			new KeyPair(signingCert.getPublicKey(), (PrivateKey) signingKey),
			CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString()
		);
		// write the content into xml
		return getDocumentAsString(document);
	}


}
