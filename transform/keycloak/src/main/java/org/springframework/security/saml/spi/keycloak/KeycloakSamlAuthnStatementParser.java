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

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.SubjectLocalityType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.assertion.AbstractStaxSamlAssertionParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAssertionQNames;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAuthnContextParser;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;

public class KeycloakSamlAuthnStatementParser extends AbstractStaxSamlAssertionParser<AuthnStatementType> {

	KeycloakSamlAuthnStatementParser() {
		super(SAMLAssertionQNames.AUTHN_STATEMENT);
	}

	@Override
	protected AuthnStatementType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws
																										 ParsingException {
		XMLGregorianCalendar
			authnInstant = XMLTimeUtil.parse(StaxParserUtil.getRequiredAttributeValue(element, SAMLAssertionQNames.ATTR_AUTHN_INSTANT));
		AuthnStatementType res = new AuthnStatementType(authnInstant);

		res.setSessionIndex(StaxParserUtil.getAttributeValue(element, SAMLAssertionQNames.ATTR_SESSION_INDEX));
		res.setSessionNotOnOrAfter(StaxParserUtil.getXmlTimeAttributeValue(element, KeycloakMissingSamlQNames.ATTR_SESSION_NOT_ON_OR_AFTER));
		return res;
	}

	@Override
	protected void processSubElement(XMLEventReader xmlEventReader, AuthnStatementType target, SAMLAssertionQNames element, StartElement elementDetail) throws ParsingException {
		switch (element) {
			case SUBJECT_LOCALITY:
				StaxParserUtil.advance(xmlEventReader);

				SubjectLocalityType subjectLocalityType = new SubjectLocalityType();
				subjectLocalityType.setAddress(StaxParserUtil.getAttributeValue(elementDetail, SAMLAssertionQNames.ATTR_ADDRESS));
				subjectLocalityType.setDNSName(StaxParserUtil.getAttributeValue(elementDetail, SAMLAssertionQNames.ATTR_DNS_NAME));

				target.setSubjectLocality(subjectLocalityType);
				break;

			case AUTHN_CONTEXT:
				target.setAuthnContext(SAMLAuthnContextParser.getInstance().parse(xmlEventReader));
				break;

			default:
				throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
		}
	}}
