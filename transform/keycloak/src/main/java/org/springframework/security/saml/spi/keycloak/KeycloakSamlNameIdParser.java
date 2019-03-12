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

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.assertion.AbstractStaxSamlAssertionParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAssertionQNames;

public class KeycloakSamlNameIdParser extends AbstractStaxSamlAssertionParser<NameIDType> {
	KeycloakSamlNameIdParser() {
		super(SAMLAssertionQNames.NAMEID);
	}

	@Override
	protected NameIDType instantiateElement(XMLEventReader xmlEventReader, StartElement nameIDElement)
		throws ParsingException {
		NameIDType target = new NameIDType();
		target.setFormat(StaxParserUtil.getUriAttributeValue(nameIDElement, SAMLAssertionQNames.ATTR_FORMAT));
		target.setNameQualifier(StaxParserUtil.getAttributeValue(nameIDElement, SAMLAssertionQNames.ATTR_NAME_QUALIFIER));
		target.setSPProvidedID(StaxParserUtil.getAttributeValue(nameIDElement, SAMLAssertionQNames.ATTR_SP_PROVIDED_ID));
		target.setSPNameQualifier(StaxParserUtil.getAttributeValue(nameIDElement, SAMLAssertionQNames.ATTR_SP_NAME_QUALIFIER));
		String nameIDValue = StaxParserUtil.getElementText(xmlEventReader);
		target.setValue(nameIDValue);
		return target;
	}

	@Override
	protected void processSubElement(XMLEventReader xmlEventReader,
									 NameIDType target,
									 SAMLAssertionQNames element,
									 StartElement elementDetail) throws ParsingException {

	}
}
