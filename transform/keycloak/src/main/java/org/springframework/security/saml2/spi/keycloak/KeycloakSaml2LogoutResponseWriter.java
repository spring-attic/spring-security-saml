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

import java.net.URI;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.springframework.security.saml2.util.Saml2DateUtils;

import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.dom.saml.v2.protocol.StatusCodeType;
import org.keycloak.dom.saml.v2.protocol.StatusDetailType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusType;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.BaseWriter;
import org.w3c.dom.Element;

import static org.keycloak.saml.common.constants.JBossSAMLConstants.CONSENT;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.DESTINATION;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.IN_RESPONSE_TO;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.ISSUER;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.LOGOUT_RESPONSE;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.STATUS;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.STATUS_CODE;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.STATUS_MESSAGE;
import static org.keycloak.saml.common.constants.JBossSAMLConstants.VALUE;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.PROTOCOL_NSURI;
import static org.springframework.security.saml2.util.Saml2DateUtils.toZuluTime;

public class KeycloakSaml2LogoutResponseWriter extends BaseWriter {

	KeycloakSaml2LogoutResponseWriter(XMLStreamWriter writer) {
		super(writer);
	}


	void writeLogoutResponse(Saml2LogoutResponseType response) throws ProcessingException {

		StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, LOGOUT_RESPONSE.get(),PROTOCOL_NSURI.get());
		StaxUtil.writeNameSpace(writer, PROTOCOL_PREFIX, PROTOCOL_NSURI.get());

		writeBaseAttributes(response);

		NameIDType issuer = response.getIssuer();
		write(
			issuer,
			new QName(ASSERTION_NSURI.get(), ISSUER.get(), ASSERTION_PREFIX)
		);

		Element sig = response.getSignature();
		if (sig != null) {
			StaxUtil.writeDOMElement(writer, sig);
		}
		ExtensionsType extensions = response.getExtensions();
		if (extensions != null && extensions.getAny() != null && !extensions.getAny().isEmpty()) {
			write(extensions);
		}

		StatusType status = response.getStatus();
		write(status);

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	private void write(StatusType status) throws ProcessingException {
		StaxUtil.writeStartElement(
			writer,
			PROTOCOL_PREFIX,
			STATUS.get(),
			PROTOCOL_NSURI.get()
		);

		StatusCodeType statusCodeType = status.getStatusCode();
		write(statusCodeType);

		String statusMessage = status.getStatusMessage();
		if (StringUtil.isNotNull(statusMessage)) {
			StaxUtil.writeStartElement(
				writer,
				PROTOCOL_PREFIX,
				STATUS_MESSAGE.get(),
				PROTOCOL_NSURI.get()
			);
			StaxUtil.writeCharacters(writer, statusMessage);
			StaxUtil.writeEndElement(writer);
		}

		StatusDetailType statusDetail = status.getStatusDetail();
		if (statusDetail != null) {
			write(statusDetail);
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	private void write(StatusCodeType statusCodeType) throws ProcessingException {
		StaxUtil.writeStartElement(
			writer,
			PROTOCOL_PREFIX,
			STATUS_CODE.get(),
			PROTOCOL_NSURI.get()
		);

		URI value = statusCodeType.getValue();
		if (value != null) {
			StaxUtil.writeAttribute(writer, VALUE.get(), value.toASCIIString());
		}
		StatusCodeType subStatusCode = statusCodeType.getStatusCode();
		if (subStatusCode != null) {
			write(subStatusCode);
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	/**
	 * Write a {@code StatusDetailType} to stream
	 */
	public void write(StatusDetailType statusDetailType) throws ProcessingException {
		StaxUtil.writeStartElement(
			writer,
			PROTOCOL_PREFIX,
			STATUS_CODE.get(),
			PROTOCOL_NSURI.get()
		);
		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	/**
	 * Write the common attributes for all response types
	 */
	private void writeBaseAttributes(StatusResponseType statusResponse) throws ProcessingException {
		// Attributes
		StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), statusResponse.getID());
		StaxUtil.writeAttribute(writer, JBossSAMLConstants.VERSION.get(), statusResponse.getVersion());
		StaxUtil.writeAttribute(
			writer,
			JBossSAMLConstants.ISSUE_INSTANT.get(),
			toZuluTime(Saml2DateUtils.toDateTime(statusResponse.getIssueInstant()))
		);

		String destination = statusResponse.getDestination();
		if (StringUtil.isNotNull(destination)) {
			StaxUtil.writeAttribute(writer, DESTINATION.get(), destination);
		}

		String consent = statusResponse.getConsent();
		if (StringUtil.isNotNull(consent)) {
			StaxUtil.writeAttribute(writer, CONSENT.get(), consent);
		}

		String inResponseTo = statusResponse.getInResponseTo();
		if (StringUtil.isNotNull(inResponseTo)) {
			StaxUtil.writeAttribute(writer, IN_RESPONSE_TO.get(), inResponseTo);
		}
	}
}
