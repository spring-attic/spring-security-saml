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

import java.io.Reader;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.namespace.QName;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.SamlKeyStoreProvider;
import org.springframework.util.Assert;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.EncryptionConstants;
import org.keycloak.saml.RandomSecret;
import org.keycloak.saml.processing.core.util.SignatureUtilTransferObject;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.keycloak.saml.common.constants.JBossSAMLConstants.ASSERTION;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.ISSUER;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;
import static org.keycloak.saml.common.util.DocumentUtil.getDocument;
import static org.keycloak.saml.common.util.DocumentUtil.getDocumentAsString;
import static org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature.configureIdAttribute;
import static org.keycloak.saml.processing.core.util.XMLEncryptionUtil.DS_KEY_INFO;
import static org.keycloak.saml.processing.core.util.XMLEncryptionUtil.encryptKey;
import static org.springframework.security.saml.saml2.signature.CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
import static org.springframework.util.StringUtils.hasText;

class KeycloakSigner {

	private final SamlKeyStoreProvider provider;

	KeycloakSigner(SamlKeyStoreProvider provider) {
		this.provider = provider;
	}

	private String signOrEncrypt(Response response, Document document) {
		try {
			Map<String, Element> assertions = getAssertions(document);

			//signOrEncrypt each assertion
			for (Assertion a : response.getAssertions()) {
				if (a.getSigningKey() != null) {
					Element e = assertions.get(a.getId());
					SignatureUtilTransferObject sig = getSignatureObject(a);
					sig.setDocumentToBeSigned(document);
					sig.setNextSibling(getIssuerSibling(e));
					document = XMLSignatureUtil.sign(sig, ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString());
				}
			}
			//encrypt each assertion
			for (Assertion a : response.getAssertions()) {
				if (a.getEncryptionKey() != null) {
					Element e = assertions.get(a.getId());
					encryptAssertion(a, e, document);
				}
			}

			//signOrEncrypt the response itself
			if (response.getSigningKey() != null) {
				SignatureUtilTransferObject sig = getSignatureObject(response);
				sig.setDocumentToBeSigned(document);
				sig.setNextSibling(getIssuerSibling(document));
				document = XMLSignatureUtil.sign(sig, ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString());
			}
			return getDocumentAsString(document);
		} catch (Exception e) {
			throw new SamlException(e);
		}
	}

	String signOrEncrypt(SignableSaml2Object signable, String xml) {
		try {

			Reader xmlReader = new StringReader(xml);
			Document document = getDocument(xmlReader);
			configureIdAttribute(document);

			//response may have nested objects to be signed
			if (signable instanceof Response) {
				return signOrEncrypt((Response) signable, document);
			}

			if (signable.getSigningKey() == null) {
				return xml;
			}
			if (signable instanceof Metadata) {
				return sign((Metadata) signable, document);
			}
			else if (signable instanceof AuthenticationRequest) {
				return sign(signable, document);
			}
			else if (signable instanceof Assertion) {
				return sign(signable, document);
			}
			else if (signable instanceof LogoutRequest) {
				return sign(signable, document);
			}
			else if (signable instanceof LogoutResponse) {
				return sign(signable, document);
			}
			else {
				throw new UnsupportedOperationException("Unable to signOrEncrypt class:" + signable.getClass());
			}
		} catch (Exception e) {
			throw new SamlException(e);
		}
	}

	private String sign(SignableSaml2Object signable, Document document)
		throws GeneralSecurityException, MarshalException, XMLSignatureException {
		SignatureUtilTransferObject sig = getSignatureObject(signable);
		sig.setDocumentToBeSigned(document);
		sig.setNextSibling(getIssuerSibling(document));
		document = XMLSignatureUtil.sign(sig, ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString());
		return getDocumentAsString(document);
	}

	private String sign(Metadata signable, Document document)
		throws GeneralSecurityException, MarshalException, XMLSignatureException {
		SignatureUtilTransferObject sig = getSignatureObject(signable);
		document = XMLSignatureUtil.sign(
			document,
			sig.getKeyName(),
			sig.getKeyPair(),
			sig.getDigestMethod(),
			sig.getSignatureMethod(),
			"#" + signable.getId(),
			sig.getX509Certificate(),
			ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString()
		);
		return getDocumentAsString(document);
	}

	private SignatureUtilTransferObject getSignatureObject(SignableSaml2Object so)
		throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		SignatureUtilTransferObject sig = new SignatureUtilTransferObject();
		sig.setDigestMethod(so.getDigest().toString());
		sig.setReferenceURI("#" + so.getId());
		sig.setSignatureMethod(so.getAlgorithm().toString());
		KeyInfo info = new KeyInfo(provider, so.getSigningKey());
		sig.setX509Certificate(info.getCertificate());
		sig.setKeyPair(info.getKeyPair());
		sig.setKeyName(so.getSigningKey().getId());
		return sig;
	}

	private Node getIssuerSibling(Document doc) {
		// Find the sibling of Issuer
		return getSibling(doc, ASSERTION_NSURI.get(), ISSUER.get());
	}

	private Node getSibling(Document doc, String namespaceURI, String localName) {
		NodeList nl = doc.getElementsByTagNameNS(namespaceURI, localName);
		if (nl.getLength() > 0) {
			Node issuer = nl.item(0);
			return issuer.getNextSibling();
		}
		return null;
	}

	private Node getIssuerSibling(Element node) {
		// Find the sibling of Issuer
		NodeList nl = node.getElementsByTagNameNS(ASSERTION_NSURI.get(), ISSUER.get());
		if (nl.getLength() > 0) {
			Node issuer = nl.item(0);
			return issuer.getNextSibling();
		}
		return null;
	}

	private Map<String, Element> getAssertions(Document doc) {
		NodeList nl = doc.getElementsByTagNameNS(ASSERTION_NSURI.get(), ASSERTION.get());
		if (nl.getLength() == 0) {
			nl = doc.getElementsByTagNameNS("*", ASSERTION.get());
			if (nl.getLength() == 0) {
				return Collections.emptyMap();
			}
		}
		Map<String, Element> result = new HashMap<>();
		for (int i = 0; i < nl.getLength(); i++) {
			Element assertion = (Element) nl.item(0);
			String id = assertion.getAttribute("ID");
			result.put(id, assertion);
		}
		return result;
	}

	private int getKeySize(DataEncryptionMethod method) {
		switch (method) {
			case AES128_CBC:
				return 128;
			case AES256_CBC:
				return 256;
			case AES192_CBC:
				return 192;
			default:
				return 192;
		}
	}

	private void encryptAssertion(Assertion assertion,
								  Element assertionElement,
								  Document document) {
		Assert.notNull(assertion, "Assertion cannot be null");
		Assert.notNull(assertion.getId(), "Assertion ID cannot be null");
		Assert.notNull(assertionElement, "Unable to find assertion with ID:" + assertion.getId());
		String encryptionAlgorithm = assertion.getDataAlgorithm().toString();
		try {
			KeyInfo info = new KeyInfo(provider, assertion.getEncryptionKey());
			int keySize = getKeySize(assertion.getDataAlgorithm());
			byte[] secret = RandomSecret.createRandomSecret(keySize / 8);
			SecretKey secretKey = new SecretKeySpec(secret, encryptionAlgorithm);
			// encrypt the Assertion element and replace it with a EncryptedAssertion element.

			String prefix = assertionElement.getPrefix();
			QName aqName = new QName(ASSERTION_NSURI.get(), ASSERTION.get(), prefix);
			QName encqName = new QName(ASSERTION_NSURI.get(), "EncryptedAssertion", prefix);


			XMLCipher cipher = null;
			EncryptedKey encryptedKey = encryptKey(
				document,
				secretKey,
				info.getKeyPair().getPublic(),
				keySize
			);


			// Encrypt the Document
			try {
				cipher = XMLCipher.getInstance(encryptionAlgorithm);
				cipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
			} catch (XMLEncryptionException e) {
				throw new SamlException(e);
			}

			Document encryptedDoc;
			try {
				encryptedDoc = cipher.doFinal(document, assertionElement);
			} catch (Exception e) {
				throw new SamlException(e);
			}

			// The EncryptedKey element is added
			Element encryptedKeyElement = cipher.martial(document, encryptedKey);

			final String wrappingElementName;

			if (!hasText(encqName.getPrefix())) {
				wrappingElementName = encqName.getLocalPart();
			}
			else {
				wrappingElementName = encqName.getPrefix() + ":" + encqName.getLocalPart();
			}
			// Create the wrapping element and set its attribute NS
			Element wrappingElement =
				encryptedDoc.createElementNS(encqName.getNamespaceURI(), wrappingElementName);

			if (hasText(encqName.getPrefix())) {
				wrappingElement.setAttributeNS(
					XMLConstants.XMLNS_ATTRIBUTE_NS_URI,
					"xmlns:" + encqName.getPrefix(),
					encqName.getNamespaceURI()
				);
			}

			// Get Hold of the Cipher Data
			NodeList cipherElements = encryptedDoc.getElementsByTagNameNS(
				EncryptionConstants.EncryptionSpecNS,
				EncryptionConstants._TAG_ENCRYPTEDDATA
			);
			if (cipherElements == null || cipherElements.getLength() == 0) {
				throw new SamlException("Missing cipher elements.");
			}
			Element encryptedDataElement = (Element) cipherElements.item(0);

			Node parentOfEncNode = encryptedDataElement.getParentNode();
			parentOfEncNode.replaceChild(wrappingElement, encryptedDataElement);

			wrappingElement.appendChild(encryptedDataElement);

			// Outer ds:KeyInfo Element to hold the EncryptionKey
			Element sigElement = encryptedDoc.createElementNS(XMLSignature.XMLNS, DS_KEY_INFO);
			sigElement.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", XMLSignature.XMLNS);
			sigElement.appendChild(encryptedKeyElement);

			// Insert the Encrypted key before the CipherData element
			NodeList nodeList = encryptedDoc.getElementsByTagNameNS(
				EncryptionConstants.EncryptionSpecNS,
				EncryptionConstants._TAG_CIPHERDATA
			);
			if (nodeList == null || nodeList.getLength() == 0) {
				throw new SamlException("Missing cipher data");
			}
			Element cipherDataElement = (Element) nodeList.item(0);
			Node cipherParent = cipherDataElement.getParentNode();
			cipherParent.insertBefore(sigElement, cipherDataElement);

		} catch (Exception x) {
			throw new SamlException("failed to encrypt", x);
		}

	}

	private String getXMLEncryptionURL(String algo, int keySize) {
		if ("AES".equals(algo)) {
			switch (keySize) {
				case 192:
					return XMLCipher.AES_192;
				case 256:
					return XMLCipher.AES_256;
				default:
					return XMLCipher.AES_128;
			}
		}
		if (algo.contains("RSA")) {
			return XMLCipher.RSA_v1dot5;
		}
		throw new SamlException("Secret Key with unsupported algorithm:" + algo);
	}


}
