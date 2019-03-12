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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.springframework.security.saml.SamlException;

import org.keycloak.saml.common.PicketLinkLogger;
import org.keycloak.saml.common.PicketLinkLoggerFactory;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAssertionQNames;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAttributeValueParser;
import org.keycloak.saml.processing.core.parsers.util.SAMLParserUtil;

import static org.springframework.security.saml.util.DateUtils.fromZuluTime;
import static org.springframework.util.StringUtils.hasText;

public class KeycloakSamlAttributeParser extends SAMLAttributeValueParser {
	private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
	private static final QName NIL =
		new QName(JBossSAMLURIConstants.XSI_NSURI.get(), "nil", JBossSAMLURIConstants.XSI_PREFIX.get());
	private static final QName XSI_TYPE =
		new QName(JBossSAMLURIConstants.XSI_NSURI.get(), "type", JBossSAMLURIConstants.XSI_PREFIX.get());

	KeycloakSamlAttributeParser() {
	}

	@Override
	public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
		StartElement element = StaxParserUtil.getNextStartElement(xmlEventReader);
		StaxParserUtil.validate(element, SAMLAssertionQNames.ATTRIBUTE_VALUE.getQName());

		Attribute nil = element.getAttributeByName(NIL);
		if (nil != null) {
			String nilValue = StaxParserUtil.getAttributeValue(nil);
			if (nilValue != null && (nilValue.equalsIgnoreCase("true") || nilValue.equals("1"))) {
				String elementText = StaxParserUtil.getElementText(xmlEventReader);
				if (elementText == null || elementText.isEmpty()) {
					return null;
				}
				else {
					throw logger.nullValueError("nil attribute is not in SAML20 format");
				}
			}
			else {
				throw logger.parserRequiredAttribute(JBossSAMLURIConstants.XSI_PREFIX.get() + ":nil");
			}
		}

		Attribute type = element.getAttributeByName(XSI_TYPE);
		if (type == null) {
			if (StaxParserUtil.hasTextAhead(xmlEventReader)) {
				return StaxParserUtil.getElementText(xmlEventReader);
			}
			// Else we may have Child Element
			XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
			if (xmlEvent instanceof StartElement) {
				element = (StartElement) xmlEvent;
				final QName qName = element.getName();
				if (Objects.equals(qName, SAMLAssertionQNames.NAMEID.getQName())) {
					return SAMLParserUtil.parseNameIDType(xmlEventReader);
				}
			}
			else if (xmlEvent instanceof EndElement) {
				return "";
			}

			// when no type attribute assigned -> assume anyType
			return parseAnyTypeAsString(xmlEventReader);
		}

		//      RK Added an additional type check for base64Binary type as calheers is passing this type
		String typeValue = StaxParserUtil.getAttributeValue(type);
		if (typeValue.contains(":string")) {
			return StaxParserUtil.getElementText(xmlEventReader);
		}
		else if (typeValue.contains(":anyType")) {
			return parseAnyTypeAsString(xmlEventReader);
		}
		else if (typeValue.contains(":base64Binary")) {
			return StaxParserUtil.getElementText(xmlEventReader);
		}
		else if (typeValue.contains(":boolean")) {
			String value = StaxParserUtil.getElementText(xmlEventReader);
			if (hasText(value) && Boolean.parseBoolean(value)) {
				return Boolean.TRUE;
			}
			else {
				return Boolean.FALSE;
			}
		}
		else if (typeValue.contains(":dateTime")) {
			String value = StaxParserUtil.getElementText(xmlEventReader);
			if (hasText(value)) {
				return fromZuluTime(value);
			}
			else {
				return null;
			}
		}
		else if (typeValue.contains(":integer")) {
			String value = StaxParserUtil.getElementText(xmlEventReader);
			if (hasText(value)) {
				return Integer.parseInt(value);
			}
			else {
				return null;
			}
		}
		else if (typeValue.contains(":anyURI")) {
			String value = StaxParserUtil.getElementText(xmlEventReader);
			if (hasText(value)) {
				try {
					return new URI(value);
				} catch (URISyntaxException e) {
					throw new SamlException(e);
				}
			}
			else {
				return null;
			}
		}

		throw logger.parserUnknownXSI(typeValue);
	}


}
