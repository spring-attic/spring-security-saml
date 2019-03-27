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

package org.springframework.security.saml2.spi.keycloak;

import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2CanonicalizationMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.security.saml2.util.Saml2X509Utils;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Optional.ofNullable;
import static org.springframework.security.saml2.model.Saml2Namespace.NS_SIGNATURE;

class KeycloakSignatureValidator {
	static Map<String, Saml2Signature> validateSignature(SamlObjectHolder parsed, List<Saml2KeyData> keys) {
		if (keys == null || keys.isEmpty()) {
			return emptyMap();
		}
		try {
			NodeList nl = parsed.getDocument().getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl == null || nl.getLength() == 0) {
				return emptyMap();
			}
			Map<String, Saml2Signature> valid = new LinkedHashMap<>();
			for (int i = 0; i < nl.getLength(); i++) {
				Node signatureNode = nl.item(i);
				Saml2Signature validSignature = validateSignature(signatureNode, keys);
				valid.put(getSignatureHashKey(validSignature), validSignature);
			}
			return valid;
		} catch (Saml2SignatureException e) {
			throw new Saml2SignatureException(
				"Signature validation against a " + parsed.getSamlObject().getClass().getName() +
				" object failed using " + keys.size() + (keys.size() == 1 ? " key." : " keys."),
				e);
		} catch (Exception e) {
			throw new Saml2SignatureException(
				"Unable to get signature for class:" + parsed.getSamlObject().getClass().getName(),
				e
			);
		}
	}

	static Saml2Signature validateSignature(Node signatureNode, List<Saml2KeyData> keys) {
		Exception last = null;
		for (Saml2KeyData key : keys) {
			Key publicKey = getPublicKey(key.getCertificate());
			KeySelector selector = KeySelector.singletonKeySelector(publicKey);
			try {
				if (validateUsingKeySelector(signatureNode, selector)) {
					Saml2Signature sig = getSignature((Element) signatureNode)
						.setValidated(true)
						.setValidatingKey(key);
					return sig;
				}
			} catch (Exception e) {
				last = e;
			}
		}
		if (last != null) {
			if (last instanceof Saml2SignatureException) {
				throw (Saml2SignatureException)last;
			}
			else {
				throw new Saml2SignatureException(last);
			}
		}
		else {
			throw new Saml2SignatureException(
				"Signature validation failed using " +
				keys.size() +
				(keys.size() == 1 ? " key." : " keys.")
			);
		}
	}

	private static XMLSignatureFactory getXMLSignatureFactory() {
		try {
			return XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
		} catch (NoSuchProviderException ex) {
			try {
				return XMLSignatureFactory.getInstance("DOM");
			} catch (Exception err) {
				throw new Saml2Exception(err);
			}
		}
	}

	private static boolean validateUsingKeySelector(Node signatureNode, KeySelector validationKeySelector)
		throws XMLSignatureException, MarshalException {
		DOMValidateContext valContext = new DOMValidateContext(validationKeySelector, signatureNode);
		XMLSignatureFactory fac = getXMLSignatureFactory();
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);
		return signature.validate(valContext);
	}

	static String getSignatureHashKey(Saml2Signature signature) {
		return getSignatureHashKey(signature.getSignatureValue(), signature.getDigestValue());
	}

	static List<Key> getPublicKeys(List<Saml2KeyData> keys) {
		return Collections.unmodifiableList(
			ofNullable(keys).orElse(emptyList())
				.stream()
				.map(k -> getPublicKey(k.getCertificate()))
				.collect(Collectors.toList())
		);
	}

	static Saml2Signature getSignature(Element n) {
		Saml2Signature result = new Saml2Signature()
			.setCanonicalizationAlgorithm(
				Saml2CanonicalizationMethod.fromUrn(
					getAttributeFromChildNode(n, NS_SIGNATURE, "CanonicalizationMethod", "Algorithm")
				)
			)
			.setDigestValue(
				getTextFromChildNode(n, NS_SIGNATURE, "DigestValue")
			)
			.setDigestAlgorithm(
				Saml2DigestMethod.fromUrn(
					getAttributeFromChildNode(n, NS_SIGNATURE, "DigestMethod", "Algorithm")
				)
			)
			.setSignatureValue(
				getTextFromChildNode(n, NS_SIGNATURE, "SignatureValue")
			)
			.setSignatureAlgorithm(
				Saml2AlgorithmMethod.fromUrn(
					getAttributeFromChildNode(n, NS_SIGNATURE, "SignatureMethod", "Algorithm")
				)
			);


		return result;
	}

	static String getSignatureHashKey(String signatureValue, String digestValue) {
		return new StringBuffer("Signature Hash Key[Sig=")
			.append(signatureValue.trim())
			.append("; Digest=")
			.append(digestValue.trim())
			.append("]")
			.toString();
	}

	static PublicKey getPublicKey(String certPem) {
		if (certPem == null) {
			throw new Saml2Exception("Public certificate is missing.");
		}

		try {
			byte[] certbytes = Saml2X509Utils.getDER(certPem);
			Certificate cert = Saml2X509Utils.getCertificate(certbytes);
			//TODO - should be based off of config
			//((X509Certificate) cert).checkValidity();
			return cert.getPublicKey();
		} catch (CertificateException ex) {
			throw new Saml2Exception("Certificate is not valid.", ex);
		} catch (Exception e) {
			throw new Saml2Exception("Could not decode cert", e);
		}
	}

	static String getAttributeFromChildNode(Element n,
											String namespace,
											String elementName,
											String attributeName) {
		NodeList list = n.getElementsByTagNameNS(namespace, elementName);
		if (list == null || list.getLength() == 0) {
			return null;
		}
		Node item = list.item(0).getAttributes().getNamedItem(attributeName);
		if (item == null) {
			return null;
		}
		return item.getTextContent();
	}

	static String getTextFromChildNode(Element n,
									   String namespace,
									   String elementName) {
		NodeList list = n.getElementsByTagNameNS(namespace, elementName);
		if (list == null || list.getLength() == 0) {
			return null;
		}
		return list.item(0).getTextContent();
	}

	static void assignSignatureToObject(Map<String, Saml2Signature> signatureMap,
										Saml2SignableObject desc,
										Element descriptorSignature) {
		if (descriptorSignature != null) {
			Saml2Signature signature = KeycloakSignatureValidator.getSignature(descriptorSignature);
			String hashKey = KeycloakSignatureValidator.getSignatureHashKey(signature);
			desc.setSignature(signatureMap.get(hashKey));
		}
	}
}
