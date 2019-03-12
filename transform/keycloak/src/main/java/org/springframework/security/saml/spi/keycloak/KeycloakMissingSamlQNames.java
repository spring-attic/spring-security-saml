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

import javax.xml.namespace.QName;

import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.parsers.util.HasQName;

public enum KeycloakMissingSamlQNames implements HasQName {

	ATTR_SESSION_NOT_ON_OR_AFTER(null, "SessionNotOnOrAfter");

	private final QName qName;

	private KeycloakMissingSamlQNames(String localName) {
		this(JBossSAMLURIConstants.ASSERTION_NSURI, localName);
	}

	private KeycloakMissingSamlQNames(HasQName source) {
		this.qName = source.getQName();
	}

	private KeycloakMissingSamlQNames(JBossSAMLURIConstants nsUri, String localName) {
		this.qName = new QName(nsUri == null ? null : nsUri.get(), localName);
	}

	@Override
	public QName getQName() {
		return qName;
	}

	public QName getQName(String prefix) {
		return new QName(this.qName.getNamespaceURI(), this.qName.getLocalPart(), prefix);
	}
}
