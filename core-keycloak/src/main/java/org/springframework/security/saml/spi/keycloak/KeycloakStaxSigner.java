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

import java.io.ByteArrayOutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.saml2.metadata.Metadata;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;

import static java.util.Arrays.asList;

public class KeycloakStaxSigner {

	public String sign(Metadata metadata,
					   String xml,
					   Key signingKey,
					   X509Certificate signingCert) {
		QName qName = new QName("urn:oasis:names:tc:SAML:2.0:metadata", "EntityDescriptor", "md");
		Reader xmlReader = new StringReader(xml);
		try {
			return sign(
				xmlReader,
				asList(qName),
				metadata.getAlgorithm().toString(),
				metadata.getDigest().toString(),
				signingKey,
				signingCert
			);
		} catch (XMLSecurityException | XMLStreamException e) {
			throw new SamlException(e);
		}
	}

	private String sign(
		Reader xmlReader,
		List<QName> namesToSign,
		String algorithm,
		String digest,
		Key signingKey,
		X509Certificate signingCert
	) throws XMLSecurityException, XMLStreamException {
		XMLSecurityProperties properties = new XMLSecurityProperties();
		List<XMLSecurityConstants.Action> actions = new ArrayList<>();
		actions.add(XMLSecurityConstants.SIGNATURE);
		properties.setActions(actions);

		properties.setSignatureAlgorithm(algorithm);
		properties.setSignatureDigestAlgorithm(digest);
		properties.setSignatureCerts(new X509Certificate[]{signingCert});
		properties.setSignatureKey(signingKey);
		properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

		for (QName nameToSign : namesToSign) {
			SecurePart securePart = new SecurePart(nameToSign, SecurePart.Modifier.Content);
			properties.addSignaturePart(securePart);
		}

		OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(xmlReader);

		XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
		xmlStreamWriter.flush();
		xmlStreamWriter.close();
		return new String(baos.toByteArray(), StandardCharsets.UTF_8);
	}
}
